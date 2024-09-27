# TEMA 1 PCOM

La pornirea executabilului fisierului `router.c`,
mai intai trebuie:
- sa citim fisierul `arp_table.txt`, care reprezinta un array static pt
strucutura `arp_table_entry` si contine adresa `MAC` asociata uneia `IPv4`
(citirea presupune si alocarea de memorie)

- sa citim fisierul primit drept primul argument in linia de comanda (practic `argv[1]`).
Acesta poate fi ori `rtable0.txt`, ori `rtable1.txt` si contine tabela de rutare, avand urmatoarea structura
`Prefix (uint32_t) ; Next hop (uint32_t) ; Mask (uint32_t) ; Interface (int)`,
pe care o voi stoca intr-un array de `struct route_table_entry`.

- sortam array-ul pt tabela de rutare, crescator dupa `longest prefix match`,
adica dupa `rt_entry.prefix & rt_entry.mask`, iar daca doua randuri au aceeasi 
valoare pentru aceasta operatie de `si logic pe biti`, crescator dupa `mask`.
Pentru sortare am folosit functia `qsort` (Quick Sort), care are o complexitate in timp logaritmica `O(N * log2(N))`

## IPv4
Este practic laboratorul 4.
Atata timp cat router-ul primeste pachete, trebuie sa faca urmatoarele verificari:
- daca pachetul curent este destinat pentru router
- daca pachetul are ca destinatie router-ul si trece prin el

- daca checksum-ul pachetului mai este inca valid (daca valoarea este diferita de checksum-ul precedent, putem spune ca pachetul a fost corupt)

- daca pachetul curent are TTL valid (verificarea TTL-ul o facem pentru ca pachetul sa nu se plimbe intr-un 'ciclu' in cadrul retei). Se decrementeaza apoi TTL-ul si se actualizeaza checksum-ul

- daca s-a trecut cu succes de toate verificarile de mai sus,
trimitem pachetul mai departe in retea:
    1. folosind logica de `longest prefix match` de la laborator, gasim adresa IPv4 a urmatorului hop in retea
    2. cautarea binara are `O(log2(N))`, deci este o metoda mai buna decat cea liniara (array-ul cu `struct route_table_entry`)
    3. adresa `MAC` asociata celei `IPv4` a urmatorului nod din tabela de rutare devin noua destinatie, iar adresa `MAC` a router-ului devine sursa de la care pachetul a plecat
    4. trimiterea efectiva a pachetului prin `send_to_link` 


## ICMP
Protocolul `ICMP` il folosesc in tema mai degraba pentru troubleshooting
cand ceva s-a intamplat gresit cu un pachet trimis prin `IPv4`, iar aici
sunt doua cazuri:
- doua de eroare, cand TTL-ul a expirat sau nu se gaseste urmatorul nod in tabela de rutare
- unul de `ICMP reply`, cand trebuie sa ii spunem sursei care a trimis pachet-ul ca router-ul este destinatia lui finala

Pentru fiecare caz, strucutra pentru `icmphdr`, trebuie sa cuprinda atat `struct ether_header`, cat si `struct iphdr`, trebuie alocata memorie pentru 
aceasta si trebuie sa ii completam field-urile.


In caz de eroare, `ICMP`-ul are niste valori specifice pentru `type` si `code`
"""
Destination unreachable (type 3, code 0) - Trimis în cazul în care nu există rută până la destinație, atunci când pachetul nu este destinat routerului.

Time exceeded (type 11, code 0) - Trimis dacă pachetul este aruncat din cauza expirării câmpului TTL.
""" (enunt)
Dar si sa cuprin primi 64 de biti ai pachetului trimis prin `IPv4`.
Aici `TTL-ul` se reseteaza cu valoarea maxima, adica 255.


In cazul de `ICMP reply` (destinatia finala a pachetului este router-ul),
mesajul `ICMP` se va trimite de la router inapoi la sursa pachetului,
deci practic se inter-schimba adresa `MAC` sursa cu destinatia.

De vreme ce trebuie sa se intoarca la ultimul hop, TTL-ul va avea aici valoarea 1.


Dupa completarea field-urilor pachetelor `ICMP`,
functia `send_to_link` se ocupa cu trimiterea efectiva a pachetului.

