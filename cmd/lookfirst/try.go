package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Idris1980/lookfirst/internal/analyze"
	"github.com/Idris1980/lookfirst/internal/arm"
	"github.com/Idris1980/lookfirst/internal/azuretry"
	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/render"
	"github.com/Idris1980/lookfirst/internal/source"
)

const tryTag = "lookfirst=try"

// try compares a Bicep or ARM template with what Azure says it would build,
// or, with --deploy, with what it actually built in a resource group that
// exists only for this and is deleted right after. Nothing is created
// without asking first.
func try(args []string) error {
	fs := flag.NewFlagSet("try", flag.ExitOnError)
	deploy := fs.Bool("deploy", false, "build the resources for real (this can cost money), read them, then delete them")
	keep := fs.Bool("keep", false, "do not delete the resource group afterwards")
	cleanup := fs.Bool("cleanup", false, "list resource groups left by earlier runs and offer to delete them")
	location := fs.String("location", "swedencentral", "Azure region for the temporary resource group")
	subscription := fs.String("subscription", "", "subscription to use (default: the one az is set to)")
	params := fs.String("parameters", "", "a parameters file for the template")
	out := fs.String("out", "lookfirst-try.html", "where to write the report")
	fromWhatIf := fs.String("from-whatif", "", "compare with a saved answer from 'az deployment group what-if --no-pretty-print' instead of asking Azure")
	region := fs.String("region", "", "AWS region for a CloudFormation template (default: the one aws is set to)")
	fromChangeSet := fs.String("from-changeset", "", "compare with a saved answer from 'aws cloudformation describe-change-set --include-property-values' instead of asking AWS")
	fs.Parse(args)

	az := azCLI{subscription: *subscription}
	aws := awsCLI{region: *region}
	if *cleanup {
		ran := false
		if _, err := exec.LookPath("az"); err == nil {
			ran = true
			if err := az.cleanup(); err != nil {
				fmt.Println("Azure:", err)
			}
		}
		if _, err := exec.LookPath("aws"); err == nil {
			ran = true
			if err := aws.cleanup(); err != nil {
				fmt.Println("AWS:", err)
			}
		}
		if !ran {
			return fmt.Errorf("neither the Azure CLI (az) nor the AWS CLI (aws) was found")
		}
		return nil
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("give one Bicep, ARM or CloudFormation template, for example: lookfirst try main.bicep")
	}
	file := fs.Arg(0)
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	switch source.Detect(file, data) {
	case source.Bicep, source.ARM:
	case source.CloudFormation:
		if *deploy {
			return fmt.Errorf("--deploy works for Azure only for now; for CloudFormation, try shows CloudFormation's free preview")
		}
		return tryAWS(aws, file, *params, *fromChangeSet, *keep, *out)
	default:
		return fmt.Errorf("%s is not a Bicep, ARM or CloudFormation template; try only works with those for now", file)
	}

	// 1. The code, as LookFirst reads it.
	projects, err := analyze.Paths([]string{file})
	if err != nil {
		return err
	}
	code := analyze.Merge(projects)

	if *fromWhatIf != "" {
		answer, err := os.ReadFile(*fromWhatIf)
		if err != nil {
			return err
		}
		resources, err := azuretry.WhatIf(answer)
		if err != nil {
			return err
		}
		return tryAzureReport(code, resources, "Azure's preview (saved)", file, *out)
	}

	// 2. Where it would go.
	acct, err := az.account()
	if err != nil {
		return err
	}
	group := "rg-lookfirst-try-" + randomHex(3)
	fmt.Printf("Subscription: %s (%s)\n", acct.Name, acct.ID)
	fmt.Printf("LookFirst will create an empty resource group %s in %s and ask Azure to preview\nthe template (what-if). Nothing else is created, and the preview is free.\n", group, *location)
	if !ask("Continue?") {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	expires := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := az.run(ctx, "group", "create", "--name", group, "--location", *location,
		"--tags", tryTag, "lookfirst-expires="+expires, "--output", "none"); err != nil {
		return err
	}
	// The group goes away whatever happens next, even after Ctrl+C.
	defer func() {
		if *keep {
			fmt.Printf("\nKept %s. Delete it when you are done:\n  az group delete --name %s --yes\n", group, group)
			return
		}
		fmt.Printf("\nDeleting %s… ", group)
		if _, err := az.run(context.Background(), "group", "delete", "--name", group, "--yes", "--no-wait"); err != nil {
			fmt.Printf("failed: %v\nDelete it yourself:\n  az group delete --name %s --yes\n", err, group)
			return
		}
		fmt.Printf("started. Check that it is gone with:\n  az group exists --name %s\n", group)
	}()

	deployArgs := []string{"--resource-group", group, "--template-file", file}
	if *params != "" {
		deployArgs = append(deployArgs, "--parameters", "@"+*params)
	}

	// 3. What Azure says it would build.
	fmt.Println("Asking Azure for a preview…")
	answer, err := az.run(ctx, append(append([]string{"deployment", "group", "what-if"}, deployArgs...),
		"--result-format", "FullResourcePayloads", "--no-pretty-print", "--output", "json")...)
	if err != nil {
		return err
	}
	resources, err := azuretry.WhatIf(answer)
	if err != nil {
		return err
	}
	label := "Azure's preview"

	// 4. Optionally, what Azure actually builds.
	if *deploy {
		fmt.Printf("\nThe template would create %d resource(s):\n", len(resources))
		for _, r := range resources {
			fmt.Printf("  %s  %s\n", r.Type, azuretry.NameFromID(r.ID, r.Type, r.Name))
		}
		fmt.Printf("They are real and can cost money until they are deleted, which happens right\nafter LookFirst has read them.\n")
		if !ask("Build them?") {
			return nil
		}
		fmt.Println("Building… (this can take several minutes)")
		dctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		if _, err := az.run(dctx, append(append([]string{"deployment", "group", "create"}, deployArgs...), "--output", "none")...); err != nil {
			fmt.Printf("The deployment did not finish: %v\nLookFirst reads what was built anyway.\n", err)
		}
		ids, err := az.run(ctx, "resource", "list", "--resource-group", group, "--query", "[].id", "--output", "tsv")
		if err != nil {
			return err
		}
		resources = nil
		if list := strings.Fields(string(ids)); len(list) > 0 {
			shown, err := az.run(ctx, append([]string{"resource", "show", "--output", "json", "--ids"}, list...)...)
			if err != nil {
				return err
			}
			if resources, err = azuretry.Resources(shown); err != nil {
				return err
			}
		}
		label = "Built in Azure"
	}

	return tryAzureReport(code, resources, label, file, *out)
}

// tryAzureReport reads Azure's answer with the same rules as the code.
func tryAzureReport(code *model.Graph, resources []azuretry.Resource, label, file, out string) error {
	built, err := azuretry.Template(resources)
	if err != nil {
		return err
	}
	azure := arm.Read([]source.File{{Path: label, Kind: source.ARM, Data: built}})
	return tryReport("Azure", code, azure, label, file, out)
}

// tryReport compares the code with the cloud's answer, already read with
// the same rules, and writes the report.
func tryReport(cloud string, code, answer *model.Graph, label, file, out string) error {
	answer.Sort()
	diff := azuretry.CompareIn(cloud, code, answer, label)

	sections := []render.Section{
		{Name: "What " + cloud + " adds to the picture", Graph: diff},
		{Name: "From the code: " + filepath.Base(file), Graph: code},
		{Name: label, Graph: answer},
	}
	render.Text(os.Stdout, sections[:1])
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	overview := []string{
		"LookFirst read the template, then compared it with " + label + ".",
		"The first part shows what " + cloud + " adds: resources and risks that are not in the code but would be in " + cloud + ", for example because of its own defaults, filled-in parameters or transforms. The other two parts show the code and " + cloud + " on their own.",
	}
	if err := render.HTML(f, sections, render.Options{Overview: overview}); err != nil {
		return err
	}
	abs, _ := filepath.Abs(out)
	fmt.Printf("\nReport: %s\n", abs)
	return nil
}

type azCLI struct{ subscription string }

func (a azCLI) run(ctx context.Context, args ...string) ([]byte, error) {
	if a.subscription != "" {
		args = append(args, "--subscription", a.subscription)
	}
	cmd := exec.CommandContext(ctx, "az", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if lines := strings.Count(msg, "\n"); lines > 12 {
			msg = strings.Join(strings.Split(msg, "\n")[:12], "\n") + "\n…"
		}
		return nil, fmt.Errorf("az %s: %s", args[0], msg)
	}
	return stdout.Bytes(), nil
}

type account struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func (a azCLI) account() (account, error) {
	if _, err := exec.LookPath("az"); err != nil {
		return account{}, fmt.Errorf("the Azure CLI (az) was not found; try needs it and your az login")
	}
	out, err := a.run(context.Background(), "account", "show", "--output", "json")
	if err != nil {
		return account{}, fmt.Errorf("not signed in to Azure? Run az login first (%v)", err)
	}
	var acct account
	err = json.Unmarshal(out, &acct)
	return acct, err
}

// cleanup lists groups that earlier runs left behind, for example after a
// crash, and deletes them if the user agrees.
func (a azCLI) cleanup() error {
	if _, err := a.account(); err != nil {
		return err
	}
	out, err := a.run(context.Background(), "group", "list", "--tag", tryTag, "--output", "json",
		"--query", `[].{name:name, expires:tags."lookfirst-expires"}`)
	if err != nil {
		return err
	}
	var groups []struct{ Name, Expires string }
	if err := json.Unmarshal(out, &groups); err != nil {
		return err
	}
	if len(groups) == 0 {
		fmt.Println("No resource groups from LookFirst are left. Nothing to delete.")
		return nil
	}
	for _, g := range groups {
		fmt.Printf("  %s  (meant to be gone by %s)\n", g.Name, g.Expires)
	}
	if !ask(fmt.Sprintf("Delete these %d resource group(s) and everything in them?", len(groups))) {
		return nil
	}
	for _, g := range groups {
		if _, err := a.run(context.Background(), "group", "delete", "--name", g.Name, "--yes", "--no-wait"); err != nil {
			fmt.Printf("  %s: %v\n", g.Name, err)
			continue
		}
		fmt.Printf("  %s: deleting\n", g.Name)
	}
	return nil
}

// ask waits for a yes. Anything else, including no input at all, is a no.
func ask(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "j", "ja":
		return true
	}
	fmt.Println("Stopped.")
	return false
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
