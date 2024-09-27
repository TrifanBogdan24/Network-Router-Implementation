// enunt tema: https://pcom.pages.upb.ro/tema1/about.html


#include <stdio.h>      
#include <arpa/inet.h>  // pt `inet_addr`
#include <netinet/in.h> // pt `ntohs`, `IPPROTO_ICMP`
#include <string.h>     // pt `memcpy`

#include "queue.h"
#include "lib.h"
#include "protocols.h"



#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_CODE_DEST_UNREACH 0

#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_CODE_TIME_EXCEEDED 0


#define BROADCAST_MAC_STR "FF:FF:FF:FF:FF:FF"
const uint8_t BROADCAST_MAC[6] = {255, 255, 255, 255, 255, 255};

#define ETHERNETTYPE_IP 0x0800

#define MAX_NR_ROWS_ARP_TABLE 100
/**
 * arp_table.txt
 * va contine `vecinii` router-ului in retea
 * (ii privim ca pe niste noduri intr-un graf)
 * fiecare vecin are o adresa IPv4 su una MAC asociata acesteia
 * 
 * 
 * Adresa IP        Adresa MAC
 * 192.168.0.2      de:ad:be:ef:00:00
 * 192.168.1.2      de:ad:be:ef:00:01
*/
struct arp_table_entry* arp_table;
int arp_table_size;




#define MAX_NR_ROWS_RTABLE 80000
/**
 * rtable0.txt; rtable1.txt (argv[1])
 * tabela de rutare
 * Prefix         Next hop        Mask             Interface
 * 192.168.0.0    192.168.0.2     255.255.255.0    0
 * 192.168.1.0    192.168.1.2     255.255.255.0    1
*/
struct route_table_entry *rtable;
int rtable_size;





/**
 * functie de cautare liniara: O(N)
 * 
 * va return randul din tabela de rutare pentru care
 * - `ip.destination & entry.mask == entry.prefix`
 * - `entry.mask` are valoarea maxima
*/
struct route_table_entry* cauta_liniar_in_tabela_de_rutare(struct iphdr *ipv4_hdr)
{
    uint32_t mask_ruta_aleasa = 0;                // adresa IPv4 a mastii (maxima)
    struct route_table_entry *ruta_aleasa = NULL;
    


    for (int i = 0; i < rtable_size; i++) {
        
        if (ntohl(ipv4_hdr->daddr & rtable[i].mask) ==
            (ntohl(rtable[i].prefix) & ntohl(rtable[i].mask))
            && ntohl(rtable[i].mask) >= mask_ruta_aleasa) {
            
            ruta_aleasa = &rtable[i];
            mask_ruta_aleasa = ntohl(rtable[i].mask);
        }
    }

    return ruta_aleasa;
}



/**
 * functie de cautare binara: O(log(N))
 * 
 * va return randul din tabela de rutare pentru care
 * - `ip.destination & entry.mask == entry.prefix`
 * - `entry.mask` are valoarea maxima
*/
struct route_table_entry* cauta_binar_in_tabela_de_rutare(struct iphdr *ipv4_hdr)
{

    uint32_t mask_ruta_aleasa = 0;                // adresa IPv4 a mastii (maxima)
    struct route_table_entry *ruta_aleasa = NULL;

    int left = 0;
    int right = rtable_size - 1;

    while (left <= right) {
        int mid = (right - left) / 2 + left;

        if (ntohl(ipv4_hdr->daddr & rtable[mid].mask) < ntohl(rtable[mid].prefix & rtable[mid].mask)) {
            left = mid + 1;
            continue;
        }

        if (ntohl(ipv4_hdr->daddr & rtable[mid].mask) > ntohl(rtable[mid].prefix & rtable[mid].mask)) {
            right = mid - 1;
            continue;
        }

        // se respecta: ntohl(ipv4_hdr->daddr & rtable[mid].mask) == ntohl(rtable[mid].prefix & rtable[mid].mask)
        if (ntohl(rtable[mid].mask) > mask_ruta_aleasa) {
            mask_ruta_aleasa = ntohl(rtable[mid].mask);
            ruta_aleasa = &rtable[mid];
        }
        right = mid - 1;
    }


    return ruta_aleasa;
}



int cmp_IPv4_addr_rtable(const void *a, const void *b)
{
    const struct route_table_entry *rtable_entry_1 = (const struct route_table_entry *) a;
    const struct route_table_entry *rtable_entry_2 = (const struct route_table_entry *) b;
    
    uint32_t first_longest_prefix = ntohl(rtable_entry_1->prefix & rtable_entry_1->mask);
    uint32_t second_longest_prefix = ntohl(rtable_entry_2->prefix & rtable_entry_2->mask);

    if (first_longest_prefix < second_longest_prefix)
        return 1;
    if (first_longest_prefix > second_longest_prefix)
        return -1;
    
    return (ntohl(rtable_entry_1->mask) < ntohl(rtable_entry_2->mask));
}

/**
 * va sorta tabele de rotare, crescator dupa `longest prefix` (prefix & mask)
 * sortare in O(N * log(N))
*/
void sort_tabela_de_rautare()
{
    qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp_IPv4_addr_rtable);
}



/**
 * folosindu-ne de fisierul `arp_table.txt`, vom afla adresa MAC a
 * unui dintre nodurile vecine router-ului,
 * in functie de adresa IPv4 a acestuia (a vecinului)
*/
uint8_t* get_mac_of_destination(uint32_t ipv4_addr)
{
    uint8_t *mac_addr = (uint8_t *) malloc(6 * sizeof(uint8_t));

    for (int i = 0; i < arp_table_size; i++) {
        
        if (arp_table[i].ip == ipv4_addr) {
        
            for (int j = 0; j < 6; j++)
                mac_addr[j] = arp_table[i].mac[j];
            return mac_addr;
        }
    }

    return NULL;
}



void send_ICMP_echo_reply(char *packet, size_t packet_length, int interface,
                            struct ether_header *ethnet_hdr, struct iphdr *ipv4_hdr)
{
    get_interface_mac(interface, ethnet_hdr->ether_shost);

    // inversam adresele MAC sursa si destinatie
    // MAC_sursa <-> MAC_destinatie
    for (int i = 0; i < 6; i++) {
        uint8_t aux = ethnet_hdr->ether_dhost[i];
        ethnet_hdr->ether_dhost[i] = ethnet_hdr->ether_shost[i];
        ethnet_hdr->ether_shost[i] = aux;
    }


    // header-ul IP
    ipv4_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ipv4_hdr->protocol = IPPROTO_ICMP;
    ipv4_hdr->ttl = 1;      // trebuie sa ajunga intr-un singur punct: inapoi la sender
    ipv4_hdr->check = 0;
    ipv4_hdr->check = htons(checksum((uint16_t *)(ipv4_hdr), sizeof(struct iphdr)));

    // header-ul ICMP
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)(icmp_hdr), sizeof(struct icmphdr)));

    // trimiterea efectiva a pachetului
    send_to_link(interface, packet, packet_length);
}



void send_ICMP_error_msg(char *packet, size_t packet_length, uint8_t type, uint8_t code,
                        int interface, struct ether_header *ethnet_hdr, struct iphdr *ipv4_hdr)
{
    get_interface_mac(interface, ethnet_hdr->ether_shost);

    // field-urile pt header-ul IPv4
    ipv4_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ipv4_hdr->protocol = IPPROTO_ICMP;
    ipv4_hdr->ttl = 255;      // TTL-ul isi ia valoarea maxima
    ipv4_hdr->check = 0;
    ipv4_hdr->check = htons(checksum((uint16_t *)(ipv4_hdr), sizeof(struct iphdr)));

    // field-urile pt header-ul ICMP
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    memset(icmp_hdr, 0, sizeof(struct icmphdr));

    // Time exceeded (TTL <= 1) -> type = 11
    // Destination unreachable (nu s-a gasit ruta) -> type = 3
    icmp_hdr->type = type;
    icmp_hdr->code = code;

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)(icmp_hdr), sizeof(struct icmphdr)));
    memcpy(icmp_hdr + sizeof(struct icmphdr), ipv4_hdr, sizeof(struct iphdr));

    // lungimea noua a pachetului
    size_t new_packet_length = 64 + sizeof(struct icmphdr) + sizeof(struct ether_header) + 2 * sizeof(struct iphdr);


    // header-ul de ETHERNET
    char *new_packet = (char *) malloc(new_packet_length);
    memcpy(new_packet, ethnet_hdr, sizeof(struct ether_header));

    // headerul de IPv4, primii 64 de biti dropped si payload-ul original
    memcpy(new_packet + sizeof(struct ether_header),
            ipv4_hdr,
            sizeof(struct iphdr));
    
    memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr),
            icmp_hdr,
            sizeof(struct icmphdr));
    
    memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
            packet + sizeof(struct ether_header),
            sizeof(struct iphdr) + 64);


    // trimiterea efectiva a pachetului
    send_to_link(interface, new_packet, new_packet_length);
}




/**
 * pt a vizualiza o adresa IPv4
 * 
 * 255.255.255.255
 * 
 * functia converteste o adresa IPv4 intr-un String
 * va returna adresa in format human-readable
*/
char* ipv4_to_string(uint32_t ip_address) {
    // lungimea maxima a unui sir IPv4 este de 15 caractere: 111.111.111.111
    char *ip_string = malloc(16 * sizeof(char)); 
    
    /**
     * MSB = Most Significant Byte (2^31) -> extremitatea stanga
     * LSB = Least Significant Byte (2^0) -> extremitatea dreapta
     * 
     * MSB [0/1] LSB 
    */
    uint8_t octet[4];
    octet[3] = (ip_address >> 24) & 0xFF;
    octet[2] = (ip_address >> 16) & 0xFF;
    octet[1] = (ip_address >> 8) & 0xFF;
    octet[0] = ip_address & 0xFF;
    
    // Format the IP address as a string
    sprintf(ip_string, "%d.%d.%d.%d", octet[0], octet[1], octet[2], octet[3]);
    
    return ip_string;
}


int equal_mac_addrs(uint8_t *addr1, uint8_t *addr2)
{
    for (int i = 0; i < 6; i++)
        if (addr1[i] != addr2[i])
            return 0;
    
    return 1;
}


int main(int argc, char *argv[])
{

    // Do not modify this line
    init(argc - 2, argv + 2);


    if (argc < 2) {
        fprintf(stderr, "Err: the program expects at least one argument,");
        fprintf(stderr, " the name of the routing table file.\n");
        fprintf(stderr, "%s [rtable.txt]\n", argv[0]);
        // numele executabilului: argv[0]
        return 1;
    }

    uint8_t *broadcast_MAC_addr = (uint8_t *) malloc(6 * sizeof(uint8_t));
    if (hwaddr_aton(BROADCAST_MAC_STR, broadcast_MAC_addr)) {
        fprintf(stderr, "Nu s-a putut obtine adresa MAC de BROADCAST\n");
        return 1;
    }


    arp_table = (struct arp_table_entry *) malloc(MAX_NR_ROWS_ARP_TABLE * sizeof(struct arp_table_entry));
    arp_table_size = parse_arp_table("arp_table.txt", arp_table);


    rtable = malloc(MAX_NR_ROWS_RTABLE * sizeof(struct route_table_entry));
    rtable_size = read_rtable(argv[1], rtable);
    sort_tabela_de_rautare();


    while (1) {

        char packet[MAX_PACKET_LEN];
        size_t packet_length;

        int interface = recv_from_any_link(packet, &packet_length);

    
		struct ether_header *ethnet_hdr = (struct ether_header *) packet;
		struct iphdr *ipv4_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));



        // adresa MAC a router-ului
        uint8_t *mac_of_router = (uint8_t *) malloc(6 * sizeof(uint8_t));
        get_interface_mac(interface, mac_of_router);


        if (ethnet_hdr->ether_type != ntohs(ETHERNETTYPE_IP)) {
			fprintf(stderr, "Pachetul nu este IPv4. Se ignora pachetul.\n");
            packet[0] = '\0';
            packet_length = 0;
			continue;
		}


        // TODO: 1. verifica daca el este destinatia
        
        if (equal_mac_addrs(ethnet_hdr->ether_dhost, mac_of_router) == 1) {
            fprintf(stdout, "Pachetul este destinat router-ului.");
        } else if (equal_mac_addrs(ethnet_hdr->ether_dhost, broadcast_MAC_addr) == 1) {
            fprintf(stdout, "Pachetul a fost trimis pe adresa de BROADCAST (catre toate lumea)");
        } else {
            // pachetul nu este pt router
            packet[0] = '\0';
            packet_length = 0;
            continue;
        }



        // compara adresa DESTINATIE IPv4 a pachetului
        // cu adresa IPv4 a router-ului
        if (ipv4_hdr->daddr == inet_addr(get_interface_ip(interface))) {
            fprintf(stdout, "Pachetul este destinat router-ului.\n");
            send_ICMP_echo_reply(packet, packet_length, interface, ethnet_hdr, ipv4_hdr);
            continue;
        }


        // TODO 2: verificare checksum
        uint16_t ipv4_checksum = ipv4_hdr->check;
		ipv4_hdr->check = 0;

        if (ipv4_checksum != htons(checksum((uint16_t *)ipv4_hdr, sizeof(struct iphdr)))) {
            fprintf(stderr, "Checksum invalid.\n");
            packet[0] = '\0';
            packet_length = 0;
            continue;
        }


        // TODO 3: verifica si actualizeaza TTL
        if (ipv4_hdr->ttl <= 1) {
            fprintf(stderr, "Time limit a expirat.\n");

            send_ICMP_error_msg(packet, packet_length, 11, 0, interface, ethnet_hdr, ipv4_hdr);
            packet[0] = '\0';
            packet_length = 0;
            continue;
        }
        ipv4_hdr->ttl--;


        // TODO 4: cautare in tabela de rutare (fisierul lui `argv[1]`)
        struct route_table_entry* new_route = cauta_binar_in_tabela_de_rutare(ipv4_hdr);

        if (new_route == NULL) {
            fprintf(stderr, "Nu s-a gasit o ruta pentru a trimite pachetul mai departe.\n");
           
            send_ICMP_error_msg(packet, packet_length, 3, 0, interface, ethnet_hdr, ipv4_hdr);
            packet[0] = '\0';
            packet_length = 0;
            continue;
        }


        // TODO 5: actualizare checksum
        ipv4_hdr->check = 0;
		ipv4_hdr->check = htons(checksum((uint16_t *) ipv4_hdr, sizeof(struct iphdr)));


        // TODO 6: rescriere adrese (MAC)
        // adresa sursa va fi adresa interfetei routerului
        // adresa destinatie = adresa MAC a urmatorului hop

        // supra-scriem adresa SURSA (a pachetului) cu ADRESA MAC a router-ului
        for (int i = 0; i < 6; i++)
            ethnet_hdr->ether_shost[i] = mac_of_router[i];


        // supra-scriem adresa DESTINATIE (a pachetului)
        // cu ADRESA MAC pt urmatorul hop (adresa o cautam in `arp_table.txt`)
        uint8_t *mac_of_next_hop = get_mac_of_destination(new_route->next_hop);
        for (int i = 0; i < 6; i++)
            ethnet_hdr->ether_dhost[i] = mac_of_next_hop[i];

        // TODO 7: trimiterea noului pachet pe interfata corespunzatoare urmatorului hp
        send_to_link(new_route->interface, packet, packet_length);
        fprintf(stdout, "Pachetul a fost trimis cu succes mai departe.\n");
    }


    return 0;
}
