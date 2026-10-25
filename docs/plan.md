# LookFirst – plan

## Problemet

Utvecklare kopierar kod från AI, kör den och hoppas på det bästa. De vet inte vad som byggs, vilka portar som öppnas, om nycklar ligger i klartext eller vad det kostar. LookFirst visar det i en bild, med ikoner och en förklaring på vanligt språk, innan något rör den riktiga miljön.

## Grundprinciper

1. **Användarvänligt först.** Man högerklickar på en fil och får ett svar. Inget konto och ingen konfiguration för att komma igång.
2. **Koden lämnar inte datorn.** Verktyget körs där koden redan finns, alltså i VS Code eller i terminalen, och behöver inget nätverk. Ingen ska behöva lita på en server.
3. **Påverkar ingenting på riktigt.** Läsläget kör aldrig koden. Körläget (senare) kör i en microVM utan riktigt nätverk och med låtsasmoln.
4. **Kommer till användaren.** Tillägget kontrollerar själv när en fil sparas eller kod klistras in och visar en diskret varning. Man ska inte behöva komma ihåg att kontrollera.
5. **Aldrig "safe".** Verktyget säger "this is what we found", aldrig att koden är säker. Skicklig skadlig kod kan gömma sig för statisk läsning, och det är det körläget finns till för.
6. **Engelska i produkten.** Gränssnitt, förklaringar och README är på engelska, men texterna ligger ännu i koden; de ska flyttas till en språkfil innan svenska läggs till. Planer och anteckningar skrivs på svenska.

## Var den körs

En motor i Go, paketerad på tre sätt:

- **VS Code-tillägg (huvudvägen):** "Show in LookFirst" via högerklick, och diagrammet öppnas i en panel bredvid koden. Det fungerar offline.
- **Kommandoradsverktyg (en .exe):** `lookfirst read main.tf` ger ett diagram som HTML och en rapport. Det fungerar också i CI.
- **Webbsida (skyltfönster):** prova med färdiga exempel. Om man klistrar in egen kod körs den via WASM i webbläsaren, och sidan har CSP `connect-src 'none'`, så att webbläsaren själv förbjuder all nätverkstrafik.

En vanlig webbsida där man klistrar in kod valdes bort som huvudväg. Användaren måste då lita på att sidan inte skickar iväg koden och att den inte ändras eller kapas i framtiden. Många företag förbjuder dessutom att kod klistras in på externa sidor.

## Säkerhet på alla fronter

- **Läsläget kör aldrig koden.** Den tolkas bara som text.
- **Motorn tål elak indata:** tak för filstorlek, nästlingsdjup och tid (YAML-bomber, enorma filer).
- **Vårt eget verktyg är ingen inkörsport:** få beroenden med låsta versioner, signerade releaser (Sigstore/cosign), SBOM och reproducerbara byggen. Tillägget begär inga onödiga rättigheter.
- **Webbpanelen i tillägget och webbsidan** har strikt CSP: inga externa skript och inget nätverk.
- **AI-förklaringen är opt-in.** Hemligheter maskeras alltid innan något skickas, och användaren ser exakt vad som skickas.
- **Öppen källkod**, så att vem som helst kan granska vad verktyget gör.
- **Run-läget** (etapp 4) har en egen hotmodell: microVM, inget riktigt nätverk och inga riktiga nycklar. Det granskas separat innan det släpps.

## Två lägen

- **Read (statisk):** läser koden och ritar vad den skulle bygga eller göra. Koden körs inte. Det här är MVP:n.
  - *IaC* (Terraform, Bicep/ARM, docker-compose, Kubernetes) ger resurser, nätverk och portar. Här är skadan störst när något går fel.
  - *Skript* (Python, JavaScript/TypeScript, shell) ger vart data skickas, vilka filer som läses eller raderas, vilka portar som öppnas, vilka paket som installeras (även påhittade) och hårdkodade hemligheter. Här finns den största gruppen användare.
- **Run (dynamisk):** kör skript (Python, Node, Go och andra) i en isolerad microVM och spelar in vad som händer: processer, filer, nätverk, paket och fällnycklar. Kommer i etapp 4.

## Vad användaren ser (Read)

1. Högerklick på en fil i VS Code och "Show in LookFirst" (eller `lookfirst read` i terminalen).
2. Ett diagram med de officiella Azure-, AWS- och Docker-ikonerna, där pilar visar vad som hänger ihop med vad.
3. Risker markeras direkt i bilden: röd kant runt brandväggen som öppnar port 22 mot 0.0.0.0/0, ett hänglås som är öppet på lagring utan kryptering, en nyckelikon på hårdkodade hemligheter.
4. Ett sammanfattningskort i vanlig engelska: "This creates 1 VM reachable from the whole internet over SSH, 1 public storage account, and stores a database password in plain text."
5. Knappen "How do I fix this?" visar en rättad version sida vid sida (etapp 2).

## Status

- **Etapp 0 klar (2026-10-23):** Terraform blir ett diagram, offline.
- **Etapp 1 klar (2026-10-24, v0.4.0):**
  - **Format:** Terraform, Bicep (kompileras lokalt med `--no-restore`), ARM, docker-compose, Kubernetes, Dockerfile, Python, JavaScript/TypeScript, shell och PowerShell.
  - **Skriptregler:** nätverk och misstänkta tjänster, nedladdning som körs, dold kod, känsliga filer, autostart, radering, portar, program som körs, paket (påhittade och felstavade namn mot inbyggda listor), hemligheter, avstängt skydd, SQL byggd av text och osäker inläsning.
  - **Syntaxkontroll:** språkets egen parser (`ast.parse`, `node --check`, `bash -n`, PowerShell Parser). Ingen av dem kör koden.
  - **Layout:** egen kolumnlayout med barycenter-sortering, egna filer för långa linjer och "+N more".
  - **VS Code-tillägg:** "Show in LookFirst", kontroll vid sparande och vid inklistring, Problems-panelen och statusraden. Paketeras per plattform med `scripts/build.ps1 -Package`.
  - **2026-10-24:** klick i bilden öppnar koden på rätt rad, rutorna visar kodens namn och typ, Bicep-symbolnamn, fler Azure-typer och ett falskt larm i ARM rättat (v0.2.1).
  - **2026-10-24, resten:** namnet LookFirst och publikt repo Idris1980/lookfirst, en bild per projekt med översikt (riskigast först), package.json och requirements.txt (installationsskript, felstavade paket, paket från adresser, extra paketservrar), rättad tolkning av `npx` och `pip install -r`, mappar med byggda filer och programfiler utan filändelse hoppas över, automatiska tester (exempel, falska larm, rapportens säkerhet), CI och signerade releaser med SBOM via GitHub Actions samt en ikon.
  - **Öppet:** om programmen som ett skript kör ska samlas i en ruta, och om texterna ska flyttas till en språkfil.
- **Etapp 2 klar (2026-10-24, v0.5.0):** "Explain and fix with AI" via VS Codes språkmodell-API (användarens Copilot eller liknande, ingen egen nyckel). Funktionen är avstängd tills användaren slår på den, och användaren ser exakt vad som skickas varje gång. Cirka 30 rader skickas, maskerade med `lookfirst excerpt` (kända nyckelformat, värden med lösenordsliknande namn, värden på raden efter namnet, PEM-block och långa slumpsträngar). Originalen läggs tillbaka bara lokalt. Svaret är på VS Codes språk och visas som ren text. Förslaget visas som en jämförelse och ändrar filen först vid Apply, som kan ångras. AI-inställningarna har scope machine, så att ett repo inte kan slå på AI eller stänga av frågan. Tester: varje exempel maskeras och läses om, och inget hemligt får finnas kvar. Tilläggets AI-hjälp testas med `node --test` i CI.
- **Etapp 3 klar (2026-10-24, v0.6.0):** webbsidan (site/ + cmd/wasm, motorn som WebAssembly, CSP som bara tillåter sidans egna filer, exempel och länkar som #example=python-helper, publiceras med pages.yml på idris1980.github.io/lookfirst), GitHub Action (action.yml: bygger från källkoden, markeringar på raderna med `--format github`, sammanfattning och kommentar med `--format markdown`, rapporten som artefakt, `--fail-on`, indata via miljövariabler mot injektion, repot granskar sina egna PR:er med lookfirst.yml), varning för platshållare i koden och i AI-förslag. Escapning av text från den granskade koden testas för både GitHub-kommandon och Markdown.
- **Etapp 4 stoppad (2026-10-24):** körläget (att köra okänd kod i en avskild miljö och se vad den gör) byggdes inte. Arbetet stoppades av ett automatiskt säkerhetsfilter på AI-sidan. Användaren valde att inte ändra något på sin dator, och det finns ingen Docker eller WSL. Etapp 5 täcker en del av samma behov för Azure-mallar.
- **Etapp 5 byggd (2026-10-24, v0.7.0, Azure-delen ej provad än):** `lookfirst try` (cmd/lookfirst/try.go, internal/azuretry). Tom tillfällig resursgrupp med taggarna lookfirst=try och lookfirst-expires, gratis what-if, med `--deploy` riktig driftsättning och avläsning med `az resource show`, rivning efteråt (även vid Ctrl+C) och `--cleanup` för kvarglömda grupper. Azures svar görs om till en ARM-mall och läses med samma regler som koden, och Compare visar det Azure lägger till (resurser som inte står i filen och risker som bara finns med Azures standardvärden). Med `--from-whatif` kan ett sparat svar jämföras utan Azure. Bara Bicep och ARM, eftersom Terraform kräver ett nytt program på datorn. Skyddsräckena från planen (Azure Policy och budget) är inte byggda. Skyddet i dag är att det frågar före allt, bara skapar en tom grupp för what-if och river direkt.
- **Efter etapp 5 (2026-10-24, v0.8.0):** valfri Anthropic-väg för AI-förklaringen (`lookFirst.ai.provider` = anthropic, nyckeln i VS Codes SecretStorage, `vscode/anthropic.js` med @anthropic-ai/sdk 0.133.0 låst och installerad med --ignore-scripts, Claude Opus 5.5 som standard med `fallbacks: "default"`). Standard är fortfarande VS Codes modeller (Copilot Free). pickModel väljer den största bland modellerna som matchar namnet. Anthropic-delen är provad mot en påhittad nyckel (avvisas med begripligt besked), inte med en riktig.
- **Test som ny användare (2026-10-25, v0.9.0):** README omskriven för nya användare (bild, prova på webben, installation med klick, AI-stegen), det tekniska flyttat till docs/. Provat med kod som en annan AI skrev (Terraform-server, WordPress med Docker, installationsskript), och LookFirst rättat efter vad det visade: inga larm för vanliga namn som `my-vnet`, varning för nyckel som Terraform skapar (`tls_private_key` hamnar i klartext i tillståndet), databasens kontrollpaneler (phpMyAdmin, Adminer, pgAdmin m.fl.) får medel nivå när de publiceras, `curl … | sudo -E bash` och nedladdning i två steg (`curl -o fil` och sedan `sh fil`) hittas, docker-gruppen varnas för, och sudo ger en varning per skript i stället för en per rad. Tydligare AI-dialog (vem som svarar när Copilot väljer modell, och vad «SECRET_1» betyder), felmeddelande som säger vilket paket som ska installeras när fel plattform valts, och mindre figurer i bilden.
- **Fler prov (2026-10-25, v0.10.0):** Bicep på webbsidan visas som en förklaring med två vägar vidare i stället för som en risk. Bilden visar sh, bash och pakethanterare, och sudos egna flaggor (`sudo -E bash`) tas inte för program. Shebang-raden räknas inte som ett program. Azure CLI i skript (PowerShell och bash, även kommandon över flera rader): det som skapas med `az … create` ritas i kolumnen "In the cloud", `--public-access all` och brandväggsregler över alla adresser ger hög risk, och `az vm create` varnar för SSH eller RDP som öppnas automatiskt eller med `--nsg-rule`. Provat mot skript från Gemini och ChatGPT.
- **ChatGPT mot Gemini (2026-10-25, v0.11.0):** samma tre frågor till ChatGPT. Rättat efter provet: lösenord med reservvärde (`${VAR:-värde}`) ger medel, nedladdning i två steg hittas även när kommandot är delat med `\`, autostart är medel och rapporteras en gång per fil (normalt för installationsskript, men också hur skadlig kod stannar kvar), och skölden visar antalet låga i stället för "no known risks".

## Etapper

### Etapp 0 – spike (bevisa kärnan)
- En Terraform-fil (azurerm) blir ett diagram med ikoner.
- Motor i Go (hashicorp/hcl) och ett kommandoradsverktyg som skriver en fristående HTML-fil med diagrammet (t.ex. Cytoscape.js inbäddat, inget hämtas från nätet).
- Klart när: tre olika exempelfiler ritas korrekt, helt offline.

### Etapp 1 – MVP Read
- Format: Terraform (azurerm + aws), docker-compose, Kubernetes-YAML, ARM-JSON (Bicep via `az bicep build`, eftersom Bicep-kompilatorn inte går att köra i webbläsaren).
- Riskregler, ett första tiotal: öppna portar mot internet, publika IP-adresser, hårdkodade hemligheter, okrypterad lagring, publik åtkomst till blob/S3, admin-lösenord i klartext, privilegierade containrar, `latest`-taggar.
- Regelbaserad sammanfattning på engelska, utan AI.
- Läsläge för skript: Python, JavaScript/TypeScript och shell (nätverksanrop, filåtkomst, portar, paket, hemligheter, `curl | bash`), med samma sorts bild.
- VS Code-tillägg med samma motor och en diagrampanel. Detta är huvudvägen för användarna.
- Automatisk kontroll vid sparande och inklistring, med en diskret varning som leder till bilden.
- Signerade releaser av .exe och tillägg.

### Etapp 2 – AI-förklaring och "fix it"
- Frivilligt (opt-in), eftersom det skickar kod ut. Hemligheter maskeras alltid innan något skickas.
- Förklaring i vanligt språk och förslag på rättad kod.

### Etapp 3 – skyltfönster och CI
- Webbsida med färdiga exempel. Motorn körs i webbläsaren via WASM, och sidan får bara hämta sina egna filer (CSP `connect-src 'self'`). Det finns ingen server som kan ta emot koden.
- GitHub Action som andra kan använda: markeringar direkt på kodraderna i pull requests, en sammanfattning i körningen, rapporten som nedladdningsbar fil, en kommentar på pull requesten och möjlighet att stoppa vid till exempel "high".
- Varning för platshållare (`YOUR_IP_ADDRESS`, `REPLACE_ME` och liknande), både i koden och i AI-förslag innan Apply. Lärdom från etapp 2.

### Etapp 4 – Run-läge
- microVM (Firecracker eller gVisor), inget nätverk som standard, låtsasmoln (LocalStack, Azurite).
- Fällnycklar: falska `AWS_SECRET_ACCESS_KEY`, `.env` och `~/.ssh/id_rsa`. Läsförsök och utskick visas i rött.
- Paketkontroll: nya eller misstänkta paket och namn som liknar kända paket.
- Tidslinje som spelar upp vad som hände.

### Etapp 5 – bron till Cleanroom

**Problemet:** läsning har en gräns. LookFirst ser vad som står i koden, men inte Azures standardvärden, moduler, variabler eller det som räknas fram först när koden körs. Ett lagringskonto där koden inte säger något om publik åtkomst kan ändå bli nåbart från internet. Det syns först när resursen finns.

**Lösningen:** knappen "Try it for real, temporarily" i LookFirst-bilden.

1. **LookFirst läser först.** Vid allvarliga risker varnar den innan något byggs.
2. **Cleanroom skapar en avgränsad resursgrupp** med skyddsräcken: Azure Policy som förbjuder publika IP-adresser och öppna portar, tillåter bara billiga storlekar, sätter en kostnadsgräns (budget) och river gruppen automatiskt efter en viss tid (till exempel 2 timmar), även om användaren glömmer.
3. **Koden körs på riktigt** i gruppen (`terraform apply` med tillståndet i miljön, eller `az deployment group create`).
4. **LookFirst läser av vad som faktiskt byggdes** (Azure Resource Graph) och ritar det bredvid bilden från koden: plan mot verklighet. Till exempel "koden sa inget om publik åtkomst, men kontot blev publikt" eller "den här resursen fanns inte i koden, den kom från en modul".
5. **Miljön rivs**, och rapporten visar vad som byggdes, månadskostnaden och skillnaderna mot koden.

Om ett skyddsräcke stoppar något är det också ett resultat: "den här koden kräver en publik IP-adress".

**Körläget från etapp 4 kan också använda Cleanroom:** skript körs i en avstängd container i Azure (utan internet, med fällnycklar) i stället för att kräva Linux och virtualisering på användarens dator.

**Svårigheter:** kostnaden på användarens eget abonnemang (automatisk rivning och budget är grunden, inte tillval), tiden (en SQL-server tar ungefär 5 minuter), bara Azure till att börja med och Terraform-tillståndet som måste rivas med miljön.

**Varför det är intressant:** hela kedjan läsa, prova avgränsat, jämföra och riva i ett och samma flöde. Befintliga verktyg gör antingen läsningen (Checkov, tfsec) eller den tillfälliga miljön, men inte båda med en jämförelse.

## Öppna frågor
- Produktnamn och om repot ska vara publikt (öppen källkod som Cleanroom?).
- Kostnadsuppskattning (Infracost) i etapp 1 eller 2?
- Licensvillkor för de officiella ikonerna (Azure och AWS tillåter användning i arkitekturdiagram, men det ska kontrolleras).

## Kända verktyg att lära av, inte konkurrera rakt mot
Checkov, tfsec och Trivy (felkonfiguration), gitleaks (hemligheter), Rover och Inframap (Terraform-diagram), Infracost (kostnad), E2B och Daytona (sandlådor för AI-kod). Ingen av dem knyter ihop bild, risk och förklaring för den som inte förstår koden. Det är vår nisch.
