# LookFirst – plan

## Problemet

Utvecklare kopierar kod från AI, kör den och hoppas på det bästa. De vet inte vad som byggs, vilka portar som öppnas, om nycklar ligger i klartext eller vad det kostar. Sandlådan visar det i en bild, med ikoner och en förklaring på vanligt språk, innan något rör den riktiga miljön.

## Grundprinciper

1. **Användarvänligt först.** Man högerklickar på en fil och får ett svar. Inget konto och ingen konfiguration för att komma igång.
2. **Koden lämnar inte datorn.** Verktyget körs där koden redan finns, alltså i VS Code eller i terminalen, och behöver inget nätverk. Ingen ska behöva lita på en server.
3. **Påverkar ingenting på riktigt.** Läsläget kör aldrig koden. Körläget (senare) kör i en microVM utan riktigt nätverk och med låtsasmoln.
4. **Kommer till användaren.** Tillägget kontrollerar själv när en fil sparas eller kod klistras in och visar en diskret varning. Man ska inte behöva komma ihåg att kontrollera.
5. **Aldrig "safe".** Verktyget säger "this is what we found", aldrig att koden är säker. Skicklig skadlig kod kan gömma sig för statisk läsning, och det är det körläget finns till för.
6. **Engelska i produkten.** Gränssnitt, förklaringar och README är på engelska, men texterna ligger i en språkfil så att svenska kan läggas till senare. Planer och anteckningar skrivs på svenska.

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
- **Etapp 1 till största delen klar (2026-10-23):**
  - **Format:** Terraform, Bicep (kompileras lokalt med `--no-restore`), ARM, docker-compose, Kubernetes, Dockerfile, Python, JavaScript/TypeScript, shell och PowerShell.
  - **Skriptregler:** nätverk och misstänkta tjänster, nedladdning som körs, dold kod, känsliga filer, autostart, radering, portar, program som körs, paket (påhittade och felstavade namn mot inbyggda listor), hemligheter, avstängt skydd, SQL byggd av text och osäker inläsning.
  - **Syntaxkontroll:** språkets egen parser (`ast.parse`, `node --check`, `bash -n`, PowerShell Parser). Ingen av dem kör koden.
  - **Layout:** egen kolumnlayout med barycenter-sortering, egna filer för långa linjer och "+N more".
  - **VS Code-tillägg:** "Show in LookFirst", kontroll vid sparande och vid inklistring, Problems-panelen och statusraden. Paketeras per plattform med `scripts/build.ps1 -Package`.
  - **2026-10-24:** klick i bilden öppnar koden på rätt rad, rutorna visar kodens namn och typ, Bicep-symbolnamn, fler Azure-typer och ett falskt larm i ARM rättat (v0.2.1).
  - **Kvar:** bilden ska delas upp per projekt när man väljer en mapp, `npx`-tolkningen ska rättas, mappar med byggda filer ska hoppas över och programmen kanske samlas i en ruta. Dessutom tester, git-repo, signerade releaser (Sigstore) och SBOM, ett produktnamn och en ikon.

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
- Webbsida med färdiga exempel, där motorn körs via WASM och CSP `connect-src 'none'` gäller.
- GitHub Action: rapport och diagram i varje pull request som ändrar IaC.

### Etapp 4 – Run-läge
- microVM (Firecracker eller gVisor), inget nätverk som standard, låtsasmoln (LocalStack, Azurite).
- Fällnycklar: falska `AWS_SECRET_ACCESS_KEY`, `.env` och `~/.ssh/id_rsa`. Läsförsök och utskick visas i rött.
- Paketkontroll: nya eller misstänkta paket och namn som liknar kända paket.
- Tidslinje som spelar upp vad som hände.

### Etapp 5 – bron till Cleanroom
- "Run this for real, temporarily" startar en tillfällig Azure-miljö via Cleanroom och river den efteråt.

## Öppna frågor
- Produktnamn och om repot ska vara publikt (öppen källkod som Cleanroom?).
- Kostnadsuppskattning (Infracost) i etapp 1 eller 2?
- Licensvillkor för de officiella ikonerna (Azure och AWS tillåter användning i arkitekturdiagram, men det ska kontrolleras).

## Kända verktyg att lära av, inte konkurrera rakt mot
Checkov, tfsec och Trivy (felkonfiguration), gitleaks (hemligheter), Rover och Inframap (Terraform-diagram), Infracost (kostnad), E2B och Daytona (sandlådor för AI-kod). Ingen av dem knyter ihop bild, risk och förklaring för den som inte förstår koden. Det är vår nisch.
