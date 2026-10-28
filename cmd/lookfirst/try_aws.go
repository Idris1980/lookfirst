package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Idris1980/lookfirst/internal/analyze"
	"github.com/Idris1980/lookfirst/internal/awstry"
	"github.com/Idris1980/lookfirst/internal/cloudformation"
	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

// CloudFormation reads a template from the command line only up to this
// size; larger ones must be uploaded to S3 first.
const maxTemplateBody = 51200

// tryAWS compares a CloudFormation template with CloudFormation's own
// preview: a change set for a new, empty stack. Nothing is built and change
// sets are free; the empty stack is deleted right after.
func tryAWS(aws awsCLI, file, params, fromChangeSet string, keep bool, out string) error {
	projects, err := analyze.Paths([]string{file})
	if err != nil {
		return err
	}
	code := analyze.Merge(projects)

	if fromChangeSet != "" {
		answer, err := os.ReadFile(fromChangeSet)
		if err != nil {
			return err
		}
		resources, err := awstry.ChangeSet(answer)
		if err != nil {
			return err
		}
		return tryAWSReport(code, resources, "CloudFormation's preview (saved)", file, out)
	}

	if info, err := os.Stat(file); err == nil && info.Size() > maxTemplateBody {
		return fmt.Errorf("%s is larger than %d bytes; CloudFormation then needs it in S3, which try does not do yet", file, maxTemplateBody)
	}
	who, err := aws.identity()
	if err != nil {
		return err
	}
	region := aws.regionName()
	if region == "" {
		return fmt.Errorf("no AWS region is set; give one with --region, for example --region eu-north-1")
	}
	stack := "lookfirst-try-" + randomHex(3)
	fmt.Printf("AWS account: %s (%s)\nRegion: %s\n", who.Account, who.Arn, region)
	fmt.Printf("LookFirst will ask CloudFormation for a change set in a new, empty stack %s.\nNothing is built, and change sets are free. The empty stack is deleted right after.\n", stack)
	if !ask("Continue?") {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	abs, _ := filepath.Abs(file)
	expires := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	create := []string{"cloudformation", "create-change-set", "--stack-name", stack, "--change-set-name", "lookfirst",
		"--change-set-type", "CREATE", "--template-body", "file://" + abs,
		"--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND",
		"--tags", "Key=lookfirst,Value=try", "Key=lookfirst-expires,Value=" + expires, "--output", "json"}
	if params != "" {
		p, _ := filepath.Abs(params)
		create = append(create, "--parameters", "file://"+p)
	}
	if _, err := aws.run(ctx, create...); err != nil {
		return err
	}
	// The empty stack goes away whatever happens next, even after Ctrl+C.
	defer func() {
		if keep {
			fmt.Printf("\nKept the stack %s. Delete it when you are done:\n  aws cloudformation delete-stack --stack-name %s\n", stack, stack)
			return
		}
		fmt.Printf("\nDeleting the empty stack %s… ", stack)
		if _, err := aws.run(context.Background(), "cloudformation", "delete-stack", "--stack-name", stack); err != nil {
			fmt.Printf("failed: %v\nDelete it yourself:\n  aws cloudformation delete-stack --stack-name %s\n", err, stack)
			return
		}
		fmt.Println("done.")
	}()

	fmt.Println("Asking CloudFormation for a preview…")
	_, waitErr := aws.run(ctx, "cloudformation", "wait", "change-set-create-complete", "--stack-name", stack, "--change-set-name", "lookfirst")
	describe := []string{"cloudformation", "describe-change-set", "--stack-name", stack, "--change-set-name", "lookfirst", "--output", "json"}
	answer, err := aws.run(ctx, append(describe, "--include-property-values")...)
	if err != nil && strings.Contains(err.Error(), "include-property-values") {
		// An older AWS CLI: the resources, but not their settings.
		fmt.Println("This AWS CLI cannot show the settings of each resource; update it for a fuller comparison.")
		answer, err = aws.run(ctx, describe...)
	}
	if err != nil {
		return err
	}
	resources, err := awstry.ChangeSet(answer)
	if err != nil {
		return err
	}
	if waitErr != nil && len(resources) == 0 {
		return waitErr
	}
	return tryAWSReport(code, resources, "CloudFormation's preview", file, out)
}

func tryAWSReport(code *model.Graph, resources []awstry.Resource, label, file, out string) error {
	built, err := awstry.Template(resources)
	if err != nil {
		return err
	}
	answer := cloudformation.Read([]source.File{{Path: label, Kind: source.CloudFormation, Data: built}})
	return tryReport("AWS", code, answer, label, file, out)
}

type awsCLI struct{ region string }

func (a awsCLI) run(ctx context.Context, args ...string) ([]byte, error) {
	if a.region != "" {
		args = append(args, "--region", a.region)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
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
		return nil, fmt.Errorf("aws %s %s: %s", args[0], args[1], msg)
	}
	return stdout.Bytes(), nil
}

type awsIdentity struct {
	Account string `json:"Account"`
	Arn     string `json:"Arn"`
}

func (a awsCLI) identity() (awsIdentity, error) {
	if _, err := exec.LookPath("aws"); err != nil {
		return awsIdentity{}, fmt.Errorf("the AWS CLI (aws) was not found; try needs it, signed in")
	}
	out, err := a.run(context.Background(), "sts", "get-caller-identity", "--output", "json")
	if err != nil {
		return awsIdentity{}, fmt.Errorf("not signed in to AWS? Run aws login or aws configure first (%v)", err)
	}
	var id awsIdentity
	err = json.Unmarshal(out, &id)
	return id, err
}

func (a awsCLI) regionName() string {
	if a.region != "" {
		return a.region
	}
	out, err := exec.Command("aws", "configure", "get", "region").Output()
	if err != nil {
		return os.Getenv("AWS_REGION")
	}
	return strings.TrimSpace(string(out))
}

// cleanup lists stacks that earlier runs left behind and deletes them if
// the user agrees. They are empty: try never builds anything in AWS.
func (a awsCLI) cleanup() error {
	if _, err := a.identity(); err != nil {
		return err
	}
	out, err := a.run(context.Background(), "cloudformation", "describe-stacks", "--output", "json",
		"--query", "Stacks[?Tags[?Key=='lookfirst' && Value=='try']].{name: StackName, status: StackStatus}")
	if err != nil {
		return err
	}
	var stacks []struct{ Name, Status string }
	if err := json.Unmarshal(out, &stacks); err != nil {
		return err
	}
	if len(stacks) == 0 {
		fmt.Println("No CloudFormation stacks from LookFirst are left in this region. Nothing to delete.")
		return nil
	}
	for _, s := range stacks {
		fmt.Printf("  %s  (%s)\n", s.Name, s.Status)
	}
	if !ask(fmt.Sprintf("Delete these %d stack(s)?", len(stacks))) {
		return nil
	}
	for _, s := range stacks {
		if _, err := a.run(context.Background(), "cloudformation", "delete-stack", "--stack-name", s.Name); err != nil {
			fmt.Printf("  %s: %v\n", s.Name, err)
			continue
		}
		fmt.Printf("  %s: deleting\n", s.Name)
	}
	return nil
}
