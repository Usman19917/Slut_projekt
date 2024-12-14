# Slut_Projekt

## Beskrivning
Det här programmet är ett Python-baserat verktyg för penetrationstestning och nätverksanalys. Det erbjuder funktioner för portskanning, nätverksskanning, sniffning av nätverkspaket samt kryptering och dekryptering av data.

## Funktioner
- Portskanning med Nmap
- Nätverksskanning med Scapy
- Sniffning av nätverkspaket
- Kryptering och dekryptering med Cryptography

### Krav
- Python 3.2
- Externa bibliotek:
    - `nmap`
    - `scapy`
    - `cryptography`

### Steg för installation
Klona repot:

git clone (https://github.com/Usman19917/Slut_projekt)

Öpnna filen i python.

## Användning

### Skanna nätverk
För att skanna nätverk använd kommandot till exampel:  
`python finish.py -n 10.2.10.0/24`

### Skanna port
Du kan välja en specifik enhet och skanna alla portar
Exampel kommandot:  `python finish.py -p 10.2.10.151`

### Sniffa nätverk
Du kan ha koll på vilka paket som skickas.  
Exampel kommandot: `sudo python finish.py --sniff eth0 --count 5`

### Generera säkerhetsnyckel
Du behöver en nyckel för att kryptera/dekryptera information.  

Eaxampel kommandot: `python finish.py --g-k`

### Kryptera information
Viktigt att tänka på är att du genererar säkerhetsnyckel
innan du på börjar krypteringen.  
Ex: `python finish.py -e "det du vill kryptera" -k "säkerhetsnyckel"`

### Dekryptera information
Viktigt att tänka på är att du har säkerhetsnyckel
innan du på börjar dekrypteringen.  
Ex: `python finish.py -d "det du vill dekryptera" -k "säkerhetsnyckel"`

## Kända begräsningar
1. Argumenten du matar in behöver vara case-sensetive.
2. Sniffning av nätverk kräver administratörsbehörighet.
3. Programmet kan inte skanna portar som är blockerade av brandväggar.
