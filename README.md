# fastgate-cli

CLI per pilotare la web UI del **Fastweb FASTGate (Technicolor FGA2130FWB** e altri
gateway Technicolor Homeware) da terminale, senza root sul modem. Guida solo
l'interfaccia web esistente via HTTP.

## Cosa funziona (e cosa devi verificare)

- **Login SRP-6a** (SHA-256, gruppo 2048 bit): implementato, autosufficiente. È la
  parte difficile e il valore vero del tool. Flusso identico alla UI Homeware:
  due POST a `/authenticate` con `CSRFtoken, I, A` poi `M`.
- **`request`** (richiesta autenticata grezza): pienamente funzionante. È il modo
  **affidabile** per cambiare i lease DHCP statici — replichi la chiamata che
  catturi dal browser.
- **`dhcp-set`**: wrapper con endpoint **INDOVINATO** per Homeware, **NON verificato**
  sul FGA2130FWB. Usalo come template, non come funzione testata.

> L'endpoint e i campi esatti del DHCP sono specifici per modello/firmware e **non
> sono pubblici**. Per questo la via sicura è: catturi la richiesta reale, poi la
> rigiochi con `request`.

## Guida rapida

```bash
cd ~/workspace/hw/fastweb-cli && source .venv/bin/activate
export FASTGATE_PASSWORD='...'

python fastgate_cli.py login-test                     # verifica credenziali (-v = debug)
python fastgate_cli.py request /path -X POST -d k=v    # rigioca chiamata catturata
python fastgate_cli.py dhcp-set --mac .. --ip ..       # wrapper TEMPLATE, da verificare
```

**Flusso DHCP (serio):**
1. `login-test` → conferma che il login va.
2. Browser `F12 → Network` → aggiungi un lease statico a mano → copia path + campi POST.
3. Replica con `request` (CSRFtoken aggiunto in automatico).
4. Quando conosci endpoint/campi veri → aggiorna `DEFAULT_DHCP_ENDPOINT` e `dhcp_set()` in `fastgate_cli.py`.

**Primo passo col modem davanti:** `python fastgate_cli.py login-test -v`. Se il login
fallisce, salva l'output `-v` e la cattura DevTools di `/authenticate`: servono per
adattare la variante SRP/CSRF del tuo firmware.

Stato: login SRP validato offline (round-trip pysrp); `request` affidabile; `dhcp-*`
sono template non testati su FGA2130FWB reale. Dettagli sotto.

## Installazione

```bash
cd ~/workspace/hw/fastweb-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Credenziali

Via flag, env o prompt:

```bash
export FASTGATE_HOST=192.168.1.1     # default
export FASTGATE_USER=admin           # default
export FASTGATE_PASSWORD='...'        # altrimenti lo chiede interattivo
```

## 1. Verifica il login

```bash
python fastgate_cli.py login-test
# -> "Login OK."   (usa -v per debug del flusso SRP/CSRF)
```

Se fallisce: il tuo firmware può usare una variante SRP diversa o un layout CSRF
diverso. Lancia con `-v`, poi confronta con la cattura reale (sotto).

## 2. Cattura la richiesta DHCP reale (una volta sola)

1. Apri la UI nel browser, **F12 → tab Network**.
2. Aggiungi/modifica a mano un lease statico DHCP (MAC → IP).
3. Trova la richiesta POST partita (es. verso `/modals/...` o un endpoint JSON).
4. Annota: **URL (path)**, **metodo**, **campi del body** (compresi i nomi esatti),
   e se usa `CSRFtoken`.

## 3. Rigioca la richiesta da terminale

Esempio generico (adatta path e campi a quelli catturati):

```bash
python fastgate_cli.py request /modals/device-modal.lp -X POST \
  -d action=SET \
  -d mac=AA:BB:CC:DD:EE:FF \
  -d ip=192.168.1.50 \
  -d hostname=server
# CSRFtoken viene aggiunto in automatico
```

Lettura (GET) di un modal/endpoint:

```bash
python fastgate_cli.py request /modals/device-modal.lp -X GET -q foo=bar
```

## 4. (Opzionale) wrapper dhcp-set — DA VERIFICARE

```bash
python fastgate_cli.py dhcp-set --mac AA:BB:CC:DD:EE:FF --ip 192.168.1.50 \
  --endpoint /modals/device-modal.lp \
  -e hostname=server
```

Se risponde errore → l'endpoint/campi indovinati non combaciano. Usa `request` con
i valori della tua cattura. Quando li conosci, aggiorna `DEFAULT_DHCP_ENDPOINT` e la
funzione `dhcp_set()` in `fastgate_cli.py`.

## Sicurezza

- Niente password in chiaro committate: `config.ini`/`.env` sono in `.gitignore`.
- TLS self-signed del modem → verifica cert off di default (`--verify-tls` per
  attivarla).
- Lo User-Agent è generico per non esporre identità/host.

## Limiti noti

- Testato nel design sul flusso Homeware documentato, **non** su un FGA2130FWB reale
  (non ne ho uno). Login e `request` sono robusti; i wrapper `dhcp-*` sono template.
- Nessun root/exploit: se Fastweb cambia la UI o blocca `/authenticate`, va adattato.
