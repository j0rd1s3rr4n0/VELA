<p align="center">
  <img src="vela/data/vela.svg" width="120" alt="Logo de VELA : une flamme bleue">
</p>

<h1 align="center">VELA</h1>

<p align="center">
  <a href="README.md">English</a> · <a href="README.es.md">Español</a> · <a href="README.ca.md">Català</a> · <a href="README.pt.md">Português</a> · <b>Français</b> · <a href="README.de.md">Deutsch</a>
</p>

<p align="center">
  <b>V</b>igilant <b>E</b>gress &amp; <b>L</b>eak <b>A</b>nalyst<br>
  <i>Votre identité réseau, toujours en veille.</i>
</p>

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/plateforme-Linux-1a1a19?logo=linux&logoColor=white">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3987e5?logo=python&logoColor=white">
  <img alt="Aucune dépendance" src="https://img.shields.io/badge/d%C3%A9pendances-aucune-0ca30c">
  <img alt="GTK 4 + libadwaita" src="https://img.shields.io/badge/GUI-GTK%204%20%2B%20libadwaita-3987e5">
  <img alt="Tests" src="https://img.shields.io/badge/tests-171%20OK-0ca30c">
  <img alt="6 langues" src="https://img.shields.io/badge/langues-FR%20·%20EN%20·%20ES%20·%20CA%20·%20PT%20·%20DE-3987e5">
  <img alt="Données de carte ODbL" src="https://img.shields.io/badge/carte-OpenStreetMap%20(ODbL)-d95926">
</p>

<p align="center">
  <img src="docs/screenshots/fr/panel.png" alt="Tableau de bord de VELA" width="100%">
</p>

VELA surveille **par où sort votre trafic** (routeur, VPN, proxies, Tor et DNS), **combien de temps** vous
utilisez chaque sortie, **les fuites** qui vous exposent et **la réputation** des IP avec lesquelles vous
communiquez. Tout en local, sous Linux, sans dépendances externes : il découvre ce qui se trouve sur votre machine
et n'active que ce qui existe réellement.

| Lettre | Ce qu'elle fait |
|---|---|
| **V**igilant | Daemon permanent, veilleur de fuites toutes les 2 s, événements du noyau (netlink) et alertes dans la barre |
| **E**gress | Suit chaque sortie : IP locale, WAN du routeur, IP publique, VPN, proxies, circuits Tor et DNS, avec sessions, compteurs `00d 00h 00m 00s` et rotation sans répétition |
| **L**eak | Détecte ce qui vous expose : connexions hors du tunnel, DNS en clair, IPv6, WebRTC, kill-switch, réseaux de VM non isolés |
| **A**nalyst | Enrichit et explique : géolocalisation locale, VirusTotal, Shodan, GreyNoise, Censys, ExoneraTor et le trajet de chaque connexion |

*Vela* est, en espagnol, la bougie qui reste allumée quand tout le monde dort : **estar en vela**, c'est veiller.

> Les captures utilisent des données réelles **anonymisées** : IP dans les plages de documentation (RFC 5737/3849),
> MAC, noms de Wi-Fi, réseaux et relais Tor inventés, et heures décalées.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Confidentialité dès la conception](#confidentialité-dès-la-conception)
- [Langues](#langues)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Architecture](#architecture)
- [État et limites](#état-et-limites)
- [Développement et sécurité du dépôt](#développement-et-sécurité-du-dépôt)

## Fonctionnalités

### Tableau de bord
En un coup d'œil : tunnel VPN, IP publique, kill-switch, DNS, session actuelle avec son compteur, l'**exposition
observable** (0–100), connexions par état, trafic de l'interface de sortie, la **topologie** complète (machine →
routeur → Internet → guard → middle → exit Tor), alertes actives, processus avec le plus de connexions,
événements des dernières 24 h et temps par pays de sortie.

### Temps réel : comment circule votre trafic
Chaque connexion est classée toutes les 2 s comme **protégée**, **fuite** ou **directe**, avec le programme
responsable, le pays, le score VirusTotal et une copie rapide. Le diagramme de flux montre **programme → couche
locale (direct / proxy / Tor) → sortie (tunnel VPN ou non) → ce que voit la destination**, et explique en clair ce
que cela signifie : par exemple, qu'un proxy *local* ne change pas l'IP que voit la destination.

<p align="center"><img src="docs/screenshots/fr/tiempo-real.png" alt="Temps réel : diagramme des routes et des connexions" width="100%"></p>

### La carte OpenStreetMap propre à l'app
Carte Web Mercator créée à partir des données OSM et **intégrée à l'app** (côtes, pays, capitales et villes,
4 niveaux de détail, noms dans votre langue). Elle fonctionne hors ligne : consulter la carte **ne demande aucune
tuile à aucun serveur**, elle ne révèle donc pas les zones que vous regardez. Couches pour les connexions en
direct, la chaîne VPN, le circuit Tor, l'historique et le temps par pays ; zoom, glisser et détail au clic.

<p align="center"><img src="docs/screenshots/fr/mapa.png" alt="Carte des connexions" width="100%"></p>

### Threat intel avec ExoneraTor
GreyNoise, VirusTotal, Shodan et Censys sur votre historique ou une liste d'IP, avec drapeau, organisation et
**détection des nœuds Tor** (consensus de votre propre Tor, liste officielle des exits et ExoneraTor). Les requêtes
ne sortent que via le VPN ou Tor ; les clés sont stockées dans `~/.config/vela/secrets.toml` (0600).

<p align="center"><img src="docs/screenshots/fr/threat-intel.png" alt="Threat intel" width="100%"></p>

### Autres écrans

| Réseaux | Alertes et actions |
|---|---|
| <img src="docs/screenshots/fr/redes.png" alt="Réseaux : interfaces, appareils vus, VM et Docker"> | <img src="docs/screenshots/fr/alertas.png" alt="Alertes avec les commandes pour les corriger"> |
| Wi-Fi, LAN, VPN, Docker et VM ; appareils vus (ARP, sans scan), isolation des réseaux de VM et empreinte des réseaux connus | Chaque problème avec des **commandes précises** pour le corriger. VELA ne les exécute jamais : vous les copiez, les relisez et les lancez |
| **Historique** | **Profils** |
| <img src="docs/screenshots/fr/historial.png" alt="Historique des sessions"> | <img src="docs/screenshots/fr/perfiles.png" alt="Profils OPSEC"> |
| Sessions de sortie avec durée, interface, VPN, IP publique et motif de fermeture | Profils générés selon ce qui se trouve sur votre système (quotidien, privé, anonyme, haut risque, labo) |

<details>
<summary><b>Réglages et consentements</b></summary>
<p align="center"><img src="docs/screenshots/fr/ajustes.png" alt="Réglages" width="100%"></p>
</details>

Il inclut aussi une **icône dans la barre** (état, profil, Tor, urgence et notifications), une **TUI** en terminal,
une **GUI web** locale (127.0.0.1 uniquement, avec jeton) et une **CLI** complète avec sortie `--json`.

## Confidentialité dès la conception

- **Observation seule par défaut.** Tout ce qui génère du trafic vers des tiers ou modifie le système exige un
  consentement explicite (`[consent]` ou la page Réglages).
- **Rien ne sort par votre IP réelle sans autorisation :** l'IP publique est vérifiée via le tunnel ; la threat
  intel, la carte et ExoneraTor passent par le VPN ou Tor.
- **Local :** géolocalisation avec les bases de Tor et du système, carte intégrée, ni CDN ni télémétrie.
- **Secrets :** clés dans un fichier 0600 jamais affiché ni envoyé au daemon ; IPC par socket UNIX 0600 avec
  vérification de l'utilisateur (`SO_PEERCRED`).
- **Honnêteté :** la base de données n'est **pas** chiffrée sans SQLCipher (permissions 0600 uniquement), et la
  géolocalisation est approximative (pays).

<details>
<summary><b>Consentements disponibles</b></summary>

Par défaut, l'outil se contente d'observer. Ces actions s'activent dans `[consent]` ; voir
[config.example.toml](config.example.toml) :

| Clé | Pourquoi elle est désactivée |
|---|---|
| `direct_ip_checks` | Le service d'écho verrait votre IP réelle |
| `active_dns_leak_test` | Un service externe voit votre IP et vos résolveurs |
| `allow_rotation_changes` | Modifie des connexions réelles |
| `allow_killswitch` | Applique des règles nftables (avec `sudo -n` ou pkexec) |
</details>

## Langues

Toute l'interface (app de bureau, barre système, CLI, TUI, GUI web, alertes et explications) est disponible en
**français, anglais, espagnol, catalan, portugais et allemand**, y compris les noms de pays et de villes de la
carte.

- **Automatique :** suit la langue du système (`LANG`) ; si ce n'est aucune des six, l'anglais.
- **La choisir :** Réglages → Langue (l'app redémarre et le daemon bascule immédiatement), `vela --lang fr status`
  ou la variable `VELA_LANG=fr`.
- **Traduire :** les catalogues se trouvent dans [`vela/locale/`](vela/locale) (`{"texte source en espagnol": "traduction"}`) ;
  `python3 -m vela.i18n check` indique ce qui manque et toute traduction qui perd une variable `{…}`.

## Installation

Prérequis : **Linux** et **Python ≥ 3.10**. L'app de bureau utilise GTK 4 + libadwaita (PyGObject) et la barre
système AyatanaAppIndicator3, déjà présents sous GNOME/Ubuntu.

```bash
git clone https://github.com/j0rd1s3rr4n0/VELA.git && cd VELA
git config core.hooksPath .githooks    # garde-fou contre les secrets et les données personnelles
python3 -m pip install --user .        # installe les commandes `vela` et `velad`
vela app --install                     # lanceur dans le menu des applications
vela daemon enable                     # surveiller dès l'ouverture de session
```

Fonctionne aussi sans installation, avec `python3 -m vela <commande>`.

Facultatif :

- `pip install geoip2`, avec les bases GeoLite2-City/ASN `.mmdb` dans `~/.local/share/GeoIP/`, pour la ville et l'ASN ;
- `pip install sqlcipher3` pour un vrai chiffrement de la base de données.

Pour observer Tor, il faut pouvoir lire son cookie de contrôle :

```bash
sudo usermod -aG debian-tor $USER
```

## Utilisation

```bash
vela app               # application de bureau
vela status            # chaîne, IP, Tor, DNS, session, compteurs, rotation, alertes
vela leakwatch         # IP publique et fuites d'IP en temps réel
vela routes            # comment circule votre trafic : programme → direct/proxy/Tor → VPN → destination
vela tui               # terminal interactif
```

<details>
<summary><b>Toutes les commandes</b></summary>

| Commande | Ce qu'elle fait |
|---|---|
| `vela tray [--install \| --remove]` | **Icône dans la barre** (AppIndicator) : état du VPN, IP, exposition et fuites ; ouvrir l'app, vérifier IP/fuites, profil, Tor, urgence, réglages rapides et notifications |
| `vela daemon enable\|disable` | Lancer le daemon avec la session (service utilisateur systemd) pour ne pas perdre d'historique |
| `vela app [--install]` | **Application de bureau native** (GTK 4 + libadwaita) ; `--install` ajoute le lanceur au menu |
| `vela leakwatch [--once] [--all]` | **IP publique et fuites d'IP en temps réel** : chaque connexion classée protégée / fuite / directe, avec le programme responsable |
| `vela networks [-n]` | Tous vos réseaux (Wi-Fi, LAN, VPN, Docker, VM) : trafic, passerelle, SSID, appareils vus, isolation des VM |
| `vela fix` | Commandes précises pour corriger chaque problème détecté (n'exécute rien) |
| `vela intel scan [IP…] [--file f] [--history]` | GreyNoise / VirusTotal / Shodan / Censys sur votre historique ou une liste (`intel keys`, `intel set-key`, `intel show`, `intel targets`) |
| `vela map [status\|build]` | **Carte OpenStreetMap propre, intégrée à l'app** (`vela/data/`, fonctionne hors ligne dans l'app native, la TUI et la GUI web). `build` la met à jour avec des données récentes : téléchargement via Tor ou le VPN (`--via direct` uniquement si vous le demandez, `--file` pour un zip déjà téléchargé) ; consulter la carte ne demande aucune tuile à personne |
| `vela network` | Interfaces, adresses classées (privée, CGNAT, ULA…), routes et policy routing |
| `vela vpn list` / `vela proxy list` | VPN et proxies détectés, avec leur état |
| `vela tor status` | Circuits avec guard, middle et exit ; guards ; vérification externe |
| `vela dns check [--active]` | Résolveurs par lien, DNS fractionné, DoT et fuites |
| `vela ip [--route tor]` | IP publique par voie (avec consentement) et IP WAN via UPnP |
| `vela sessions` / `vela counters` / `vela history` | Sessions, compteurs `00d 00h 00m 00s` et chronologie |
| `vela watch` | Événements en temps réel (nécessite le daemon) |
| `vela rotate [tor\|proxy\|vpn] [--dry-run]` | Rotation sûre ou état de la rotation |
| `vela leaks check [--active]` | Diagnostics avec preuve, méthode, limites et confiance |
| `vela profiles [activate X \| correlation \| generate [--write]]` | Profils, risque de corrélation et génération de profils adaptés au système |
| `vela audit [--html f.html]` | Audit de confidentialité |
| `vela stats --period day\|week\|month` | Statistiques et anomalies |
| `vela export --format json\|csv\|html --out …` | Exporter l'historique |
| `vela killswitch preview\|apply --yes\|release` | Kill-switch nftables (table propre) |
| `vela panic` / `vela resume` | Mode urgence (ne supprime aucune donnée) |
| `vela purge --days N --yes` | Supprimer l'ancien historique |
| `vela config show\|init\|edit` / `vela doctor` | Configuration et diagnostic de l'installation |

Toutes les commandes acceptent `--json` et `--lang`. Sans le daemon, la CLI, la TUI et la GUI exécutent le moteur
dans leur propre processus, mais n'enregistrent pas de sessions.
</details>

## Architecture

```mermaid
flowchart LR
  subgraph Système
    K[/proc · netlink · ip · nft/]
    T[Tor ControlPort]
    N[NetworkManager · libvirt · Docker]
  end
  subgraph velad["velad (daemon)"]
    D[Découverte] --> E[Moteur]
    L[Veilleur de fuites] --> E
    I[Threat intel · ExoneraTor] --> E
    E --> S[(vela.db · SQLite 0600)]
  end
  K --> D & L
  T --> E
  N --> D
  E <-->|socket UNIX 0600| A[App GTK 4]
  E <--> B[Barre système]
  E <--> C[CLI · TUI · GUI web]
```

Détails dans [ARCHITECTURE.md](ARCHITECTURE.md) (en espagnol).

## État et limites

<details>
<summary><b>Matrice des capacités</b> (validée le 2026-10-09 sous Ubuntu 26.04, Python 3.14)</summary>

Légende :

- ✅ implémenté et testé (tests automatiques et/ou exécution réelle sur cette machine) ;
- 🟡 implémenté, validation réelle en attente ;
- ⛔ indisponible en raison d'une limite de l'environnement ;
- ⏳ en attente.

| Fonctionnalité | État | Preuve |
|---|---|---|
| Découverte des capacités (5 états) | ✅ | tests + `vela discover` réel |
| Interfaces, routes, route effective, classification IPv4/IPv6/CGNAT/ULA | ✅ | tests + `vela network` réel |
| Événements netlink | ✅ | daemon réel : « netlink : événements actifs » |
| Tor : SAFECOOKIE, circuits, guard/middle/exit, flux, guards | ✅ | faux serveur + 22 circuits réels |
| Tor : IP de sortie via check.torproject.org (IsTor) | ✅ | réel : 185.220.101.140 confirmé |
| Tor : NEWNYM avec limite de fréquence et sans répéter l'exit | ✅ / 🟡 | testé avec des mocks et un dry-run réel ; NEWNYM réel non lancé (sans consentement) |
| DNS par lien (systemd-resolved), DNS fractionné, DoT | ✅ | tests + `vela dns check` réel |
| DNS effectif et chiffré : WARP DoH, cloudflared, dnscrypt/stubby, DoT, DoH de Firefox/Chromium ; route du DoH | ✅ | tests + réel : WARP DoH via `proton0` |
| Kill-switch des clients (ProtonVPN, Mullvad, NordVPN) + vérification par les routes « et si le tunnel tombe ? » | ✅ / 🟡 | ProtonVPN réel vérifié (IPv4/IPv6) ; Mullvad/NordVPN non validés (non installés) |
| Clients VPN snap/flatpak (ProtonVPN) et serveur VPN déduit du nom de la connexion | ✅ | réel : `ProtonVPN CH-DE#2` |
| Génération de profils (quotidien, privé, anonyme, haut risque, labo) et politiques `require_killswitch`/`dns_policy` | ✅ | tests + profils réels évalués en direct |
| Fuites passives : IPv6, tunnel, DNS, proxy exposé, fuseau horaire, MAC, kill-switch | ✅ | tests + constats réels |
| Surveillance de tous les réseaux : trafic, voisins ARP (sans scan), empreinte réseau, changement de MAC de la passerelle (ARP spoofing), nouveaux appareils, Wi-Fi ouvert, isolation des réseaux libvirt | ✅ | tests + réel : a détecté `pentest-isolated` avec NAT |
| IP publique uniquement via le tunnel (`public_ip.require_tunnel`) | ✅ | tests + réel : ignorée quand le VPN est tombé |
| IP publique en temps réel (toutes les 60 s avec tunnel + immédiate au changement de route) et détection de « Internet voit votre IP réelle » | ✅ / 🟡 | tests ; validation réelle en attente d'une reconnexion du VPN |
| Veilleur de fuites en temps réel (sockets du noyau toutes les 2 s, programme responsable, fuites DNS, réaction automatique avec kill-switch) | ✅ | tests + réel : 29 connexions directes détectées avec le VPN coupé |
| Remédiation par commandes (`vela fix`, GUI avec bouton copier) | ✅ | tests + exécution réelle |
| Threat intel : GreyNoise | ✅ | tests + requête réelle via Tor |
| Threat intel : VirusTotal / Shodan | ✅ | validés avec les vraies clés de l'utilisateur (score VT, ports Shodan) |
| Threat intel : Censys | 🟡 | implémenté et testé avec des réponses simulées ; pas de clé pour valider |
| Géolocalisation avec drapeau, organisation et score VT dans Temps réel et Threat intel | ✅ | tests + données réelles |
| Icône dans la barre avec état et commandes + notifications de bureau | ✅ | réel : enregistrée dans la barre GNOME, menu vérifié via D-Bus |
| Persistance : daemon avec la session (systemd), réglages et clés API depuis l'app | ✅ | tests + service actif |
| GUI native GTK 4 + libadwaita (tableau de bord, réseaux, carte cairo, historique, alertes, intel, profils, notifications) | ✅ | captures réelles rendues par GTK |
| Test actif de fuites DNS (bash.ws) | 🟡 | implémenté ; non lancé (nécessite un consentement) |
| Test WebRTC dans la GUI | 🟡 | implémenté ; non lancé dans un navigateur |
| IP publique directe / par proxy | 🟡 | implémenté ; désactivé sans consentement |
| IP WAN via UPnP-IGD + CGNAT/double NAT | 🟡 | implémenté ; votre routeur ne répond pas à UPnP |
| Sessions, intervalles, compteurs, persistance, récupération | ✅ | tests + daemon réel |
| Moteur de rotation (sélecteur, délai, exclusions, limites, rollback, fail-closed) | ✅ | 12 tests avec un backend simulé |
| Adaptateurs VPN NetworkManager / wg-quick / Mullvad | 🟡 | implémentés ; non validés. ProtonVPN (app graphique v4) n'a pas de CLI pour changer de serveur : observation seule |
| Relais pour faire tourner les proxies | ✅ | test avec des upstreams locaux |
| Kill-switch nftables | ✅ / 🟡 | règles testées et aperçu réel ; non appliqué (consentement et sudo) |
| Profils, Correlation Risk Engine, anomalies, statistiques, Exposure Score | ✅ | tests |
| Export JSON/CSV/HTML, audit de confidentialité, doctor | ✅ | exécution réelle |
| IPC (0600, SO_PEERCRED, liste blanche, événements) | ✅ | tests + permissions réelles |
| CLI | ✅ | toutes les commandes exécutées contre le système réel |
| TUI (curses) | ✅ / 🟡 | démarrage et rendu réels ; navigation interactive non vérifiée par moi |
| GUI web (jeton, Host/Origin, CSP, tableau de bord, carte, chronologie) | ✅ | tests + navigateur réel sans erreurs de console |
| Routes du trafic (programme → proxy/Tor/direct → VPN → destination), `vela routes` + diagramme dans Temps réel | ✅ / 🟡 | tests + données réelles (Tor et direct sans VPN) ; proxy local réel et proxy chaîné uniquement avec des tests simulés (aucun proxy sur la machine) |
| Proxy HTTP vs serveur web (sonde CONNECT) | ✅ | tests + :8080 réel identifié comme serveur web |
| Carte de base OpenStreetMap intégrée (Mercator, 4 niveaux de détail, côtes, pays, capitales et villes ; hors ligne ; aussi TUI et GUI web) | ✅ | tests + vraies données OSM téléchargées via Tor et captures de l'app native ; GUI web vérifiée uniquement par tests et `node --check` |
| Interface en 6 langues (fr, en, es, ca, pt, de) avec changement à chaud dans le daemon et noms de la carte traduits | ✅ | tests (catalogues complets, variables intactes) + captures réelles dans les 6 langues |
| Frontières entre pays sur la carte | ⏳ | non incluses (les données de frontières OSM pèsent des centaines de Mo) |
| Ville / ASN | ⛔ | pas de base `.mmdb` sur le système (facultatif) |
| Chiffrement de la base de données | ⛔ | SQLCipher non installé : la base n'est **pas** chiffrée, seulement protégée par des permissions 0600 |
| Windows et macOS | ⏳ | le cœur est propre à Linux (/proc, /sys, netlink, nftables) |
| Proxies PAC/WPAD : évaluation du script | ⏳ | détectés, mais le script PAC n'est pas évalué |
</details>

- La géolocalisation est locale et approximative (pays). **Ce n'est pas l'emplacement physique réel** des serveurs.
- `NEWNYM` ne garantit pas un exit différent. L'outil ne touche jamais aux guards et ne fixe pas `ExitNodes`.
- Tor Browser, s'il est détecté sur le port 9151, est seulement observé : sa rotation se fait par « Nouvelle identité ».
- Séparer les profils réseau n'empêche pas la corrélation par cookies, comptes ou empreinte du navigateur.

## Développement et sécurité du dépôt

```bash
python3 -m unittest discover -s tests -t .
```

171 tests avec des mocks et des backends simulés (faux serveur de contrôle Tor avec un vrai SAFECOOKIE, rotation
avec échecs et rollback, fuites simulées, IPC, sécurité de la GUI, faux proxy SOCKS5, carte OSM, migration,
garde-fou git et traductions). Aucun ne touche à la connectivité réelle.

Le dépôt inclut un garde-fou (`vela/gitguard.py`) qui s'exécute automatiquement via les hooks de `.githooks/`
(`git config core.hooksPath .githooks` après le clonage) :

- **pre-commit** : bloque les fichiers personnels (`.devlogs/`, bases de données, `secrets.toml`, `config.toml`,
  réglages de l'app, cookies Tor, configurations VPN, clés…), les motifs de secrets (clés privées, PrivateKey
  WireGuard, jetons GitHub/AWS/Google/Slack, `api_key = "…"`) et les **valeurs exactes de votre machine** : vos clés
  d'API et vos IP réelles, sans les stocker nulle part.
- **pre-push** : vérifie chaque commit sur le point d'être publié (y compris ce qui a été supprimé ensuite, car cela
  reste dans l'historique) et bloque si l'e-mail de l'auteur n'est pas anonyme (`…@users.noreply.github.com`).
- `python3 -m vela.gitguard all` : vérifie tout ce qui se trouve déjà dans le dépôt.

Il n'affiche jamais le secret trouvé, seulement le fichier, la ligne et le type. `user.useConfigOnly=true` empêche
git d'inventer votre identité à partir de votre nom d'utilisateur et du nom de la machine.

### Migration depuis OPSecTools

VELA s'appelait *OPSecTools* (commandes `opsec`/`opsecd`). La première commande `vela` déplace vos données
(`~/.config`, `~/.local/share`, `~/.local/state` et `~/.cache` de `opsectools` vers `vela`, avec `opsec.db` →
`vela.db`), remplace le service `opsecd` par `velad` s'il était activé et renouvelle le démarrage automatique de la
barre et le lanceur. Elle n'écrase jamais de données plus récentes et n'agit pas tant que l'ancien daemon tourne.

## Licence et crédits

- Données de la carte : © OpenStreetMap contributors, [ODbL 1.0](https://www.openstreetmap.org/copyright)
  (voir [vela/data/OSM-ATTRIBUTION.txt](vela/data/OSM-ATTRIBUTION.txt)).
- Licence du code : à définir.
