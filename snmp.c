#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


#include "nms_sm.h"
#include "nms_core.h"
#include "nms_char_io.h"
#include "nms_db_api.h"
#include "nms_logger.h"
#include "nms_db.h"

#include "nms.h"
#include "ext_controller.h"
#include "network.h"
#include "controller.h"
#include "snmp_set.h"
#include "snmp_variable.h"

#include "core_statget.h"

#define SNMP_TYPE_INTEGER 0x02
#define SNMP_TYPE_OCTET_STRING 0x04
#define SNMP_TYPE_NULL 0x05
#define SNMP_TYPE_OBJECT_IDENTIFIER 0x06
#define SNMP_TYPE_SEQUENCE 0x30
#define SNMP_TYPE_IPADDRESS 0x40
#define SNMP_TYPE_COUNTER32 0x41
#define SNMP_TYPE_GAUGE32 0x42
#define SNMP_TYPE_TIMETICKS 0x43
#define SNMP_TYPE_OPAQUE 0x44
#define SNMP_TYPE_COUNTER64 0x46



// skip section header
uint8_t *skip_header(uint8_t *addr) {
    addr++;
    if(*addr & 0x80)
        return addr + 1 + (*addr & 3);
    else
        return addr + 1;
}

uint16_t get_item_data_length(uint8_t *addr) {
    addr++;
    if(*addr == 0x81)
        return *(addr + 1);

    if(*addr == 0x82)
        return (*(addr + 1) << 8) + *(addr + 2);

    return *addr;
}

uint8_t *skip_item(uint8_t *addr) {
    addr++;
    if(*addr == 0x81)
        return addr + 2 + *(addr + 1);

    if(*addr == 0x82)
        return addr + 3 + (*(addr + 1) << 16) + *(addr + 2);

    return addr + 1 + *addr;
}



uint32_t get_snmp_digital_item(uint8_t *addr) {
    uint32_t value = 0;
    // printf("TYPE=%i LEN=%i\r\n", *addr, *(addr+1));
    switch(*addr) {
        case 0x2:
        case 0x41:
        case 0x46:
        case 0x42: {
            addr++;
            uint8_t length = *addr++;
            if(*addr & 0x80)
                value = ~value;
            do {
                value = (value << 8) | *addr++;
            } while(--length);
        } break;

        default:
            printf("WRONG TYPE=%i\n", *addr);
            break;
    }
    return value;
}


int convert_bytes_to_int(unsigned char *data, size_t byte_length, int is_big_endian) {
    int result = 0;

    if(is_big_endian) {
        // Big-endian: Most significant byte first
        for(size_t i = 0; i < byte_length; i++) {
            result |= data[i] << (8 * (byte_length - i - 1)); // Shift left by the appropriate amount
        }
    } else {
        // Little-endian: Least significant byte first
        for(size_t i = 0; i < byte_length; i++) {
            result |= data[i] << (8 * i); // Shift left by the appropriate amount
        }
    }

    return result;
}
void value_check_save_log(uint32_t *ext_controller_trow, snmp_variable_p *snmp_variable, int value_OID, char value_text[5]) {
    switch(snmp_variable->value_check) {
        case 1:
            printf("SNMP_VARIABLE_VALUE_CHECK_LESS_THAN\n");
            break;
        case 2: // the value shall be larger than the parameter  el valor debe ser mas grande que el parametro
            if(snmp_variable->is_value_check == 0) {
                printf("SNMP_VARIABLE_VALUE_CHECK_GREATER_THAN\n");
                if(value_OID < snmp_variable->ref_value) {
                    nms_extended_event(*ext_controller_trow, *ext_controller_trow, NMS_EVENT_EXT_CONTROLLER_SNMP, 0, value_text);
                    snmp_variable->is_value_check = 1;
                    snmp_variable->tx_stat_num = value_OID;
                }

            } else {
                if(value_OID != snmp_variable->tx_stat_num) {
                    if(value_OID < snmp_variable->ref_value) {
                        nms_extended_event(*ext_controller_trow, *ext_controller_trow, NMS_EVENT_EXT_CONTROLLER_SNMP, 0, value_text);
                        snmp_variable->is_value_check = 1;
                        snmp_variable->tx_stat_num = value_OID;
                    } else {
                        snmp_variable->is_value_check = 0;
                        snmp_variable->tx_stat_num = 0;
                    }
                }
            }

            break;
        case 3:
            printf("SNMP_VARIABLE_VALUE_CHECK_DELTA_LESS_THAN\n");
            break;
        case 4:
            printf("SNMP_VARIABLE_VALUE_CHECK_DELTA_GREATER_THAN\n");
            break;
        case 5:
            printf("SNMP_VARIABLE_VALUE_CHECK_MODULE_LESS_THAN\n");
            break;
    }
}
void print_snmp_response_message(uint8_t *packet_buffer,
                                 uint32_t snmp_variable_trow, snmp_context_p *snmp) {
    // P_EXT_CONTROLLER(ext_controller_trow);
    // P_SNMP_VARIABLE(snmp_variable_trow);


    uint8_t *addr = packet_buffer;

    // Navegar hasta el valor
    addr = skip_header(addr); // Skip main sequence
    addr = skip_item(addr);   // Skip version
    addr = skip_item(addr);   // Skip community
    addr = skip_header(addr); // Skip PDU header
    addr = skip_item(addr);   // Skip request ID
    addr = skip_item(addr);   // Skip error status
    addr = skip_item(addr);   // Skip error index
    addr = skip_header(addr); // Skip varbind sequence
    addr = skip_header(addr); // Skip varbind entry
    addr = skip_item(addr);   // Skip OID

    uint8_t value_type = *addr;         // Tipo del valor
    uint8_t value_length = *(addr + 1); // Longitud del valor
    uint8_t *value_data = addr + 2;     // Puntero a los datos del valor
    switch(value_type) {
        case 0x02: // INTEGER
        {
            int value = convert_bytes_to_int(value_data, value_length, 1);
            // printf("Valor: %d (longitud: %d bytes)\n", value, value_length);
            snmp->variables[snmp_variable_trow].value_type = 0x02;
            snmp->variables[snmp_variable_trow].value = value;
            break;
        }
        case 0x04: // OCTET STRING
        {
            break;
        }
        case SNMP_TYPE_TIMETICKS: // TimeTicks
        {
            uint32_t timeticks_value = convert_bytes_to_int(value_data, value_length, 1);

            // Calcular los componentes
            uint32_t days = timeticks_value / (100 * 60 * 60 * 24);
            timeticks_value %= (100 * 60 * 60 * 24);

            uint32_t hours = timeticks_value / (100 * 60 * 60);
            timeticks_value %= (100 * 60 * 60);

            uint32_t minutes = timeticks_value / (100 * 60);
            timeticks_value %= (100 * 60);

            double seconds = timeticks_value / 100.0;

            char timeticks_str[64];
            snprintf(timeticks_str, sizeof(timeticks_str),
                     "%u:%u:%02u:%.2f",
                     days, hours, minutes, seconds);
            snmp->variables[snmp_variable_trow].value_type = SNMP_TYPE_TIMETICKS;
            snmp->variables[snmp_variable_trow].value = timeticks_value;
            // printf("System Uptime: %s\n", timeticks_str);
            break;
        }
        case SNMP_TYPE_GAUGE32: // Gauge32
        {
            uint32_t gauge_value = convert_bytes_to_int(value_data, value_length, 1);
            // printf("Converted Gauge32: %u\n", gauge_value);

            char gauge_str[64];
            snprintf(gauge_str, sizeof(gauge_str), "%u", gauge_value);
            snmp->variables[snmp_variable_trow].value_type = SNMP_TYPE_GAUGE32;
            snmp->variables[snmp_variable_trow].value = gauge_value;

            break;
        }
        case SNMP_TYPE_COUNTER32: // Counter32
        {
            uint32_t counter_value = convert_bytes_to_int(value_data, value_length, 1); // Cambiado a 1 para big-endian
            // printf("Converted Counter32: %u\n", counter_value);

            char counter_str[64];
            snprintf(counter_str, sizeof(counter_str), "%u", counter_value);
            snmp->variables[snmp_variable_trow].value_type = SNMP_TYPE_COUNTER32;
            snmp->variables[snmp_variable_trow].value = counter_value;
            break;
        }
        case SNMP_TYPE_OBJECT_IDENTIFIER: // Object Identifier
        {
            break;
        }
        case SNMP_TYPE_IPADDRESS: // IP Address
        {
            // Validar que la longitud sea 4 bytes
            if(value_length != 4) {
                printf("Invalid IP Address length: %d (expected 4 bytes)\n", value_length);
                break;
            }

            // Formar la dirección IP
            char ip_address[16] = {0}; // Buffer para "xxx.xxx.xxx.xxx\0"
            snprintf(ip_address, sizeof(ip_address), "%u.%u.%u.%u",
                     value_data[0], // Primer octeto
                     value_data[1], // Segundo octeto
                     value_data[2], // Tercer octeto
                     value_data[3]  // Cuarto octeto
            );

            // printf("Converted IP Address: %s\n", ip_address);
            snmp->variables[snmp_variable_trow].value_type = SNMP_TYPE_IPADDRESS;
            memcpy(&snmp->variables[snmp_variable_trow].value, value_data, 4);
            break;
        }
        default:
            break;
    }
}
void parse_snmp_packet(uint8_t *addr, snmp_context_p *snmp) {
    // printf("IN_RQ=%i\n", *addr);
    uint8_t *original_addr = addr;
    snmp->vars_received = 0;
    if(*addr == 0x30) {


        addr = skip_header(addr);
        // skip version and community
        addr = skip_item(addr);
        addr = skip_item(addr);
        // check SNMP REPLY
        // printf("IN_RQ_TYPE=%i\n", *addr);
        if(*addr == 0xA2) {

            addr = skip_header(addr);
            snmp->request_id = get_snmp_digital_item(addr);
            // printf("SNMP RP ID=%X\n", snmp->request_id);
            uint32_t controller_id = (snmp->request_id >> 12) & 0x0F;

            P_EXT_CONTROLLER(controller_id);

            //  skip ID
            addr = skip_item(addr);

            snmp->error_code = *(addr + 2);
            // check request error
            if(*(addr + 2) == 0) {
                // skip error and error index
                addr = skip_item(addr);
                snmp->error_index = *(addr + 2);
                addr = skip_item(addr);

                int request_length = get_item_data_length(addr);
                addr = skip_header(addr);
                if(ext_controller->mode == EXT_CONTROLLER_MODE_SNMP) {
                    addr = skip_header(addr);
                    uint16_t variable_id = (snmp->request_id >> 16) & 0xF;
                    print_snmp_response_message(original_addr, variable_id, snmp);
                    snmp->vars_received = 1;
                    //printf("parse_snmp_packet request_id=%i controller_id=%i controller_name=%s variable_id=%i \r\n", snmp->request_id, controller_id, ext_controller->name, variable_id);

                    return;
                }
            }
        } else
            snmp->error_code = 100;
    } else
        snmp->error_code = 101;
    // printf("CODE=%i ID=%X\n", snmp->error_code, snmp->request_id);
}



void oid_to_bytes(const char *oid_str, unsigned char *oid_bytes, size_t *oid_length) {
    size_t i = 0;

    // Copy the OID string to avoid modifying the original
    char oid_copy[strlen(oid_str) + 1];
    strcpy(oid_copy, oid_str);

    // Tokenize the OID string
    char *token = strtok(oid_copy, ".");

    // First part: handle the first two components (1.3)
    int first = atoi(token);
    token = strtok(NULL, ".");
    int second = atoi(token);
    oid_bytes[i++] = (unsigned char)(first * 40 + second);

    // Process the remaining components
    while((token = strtok(NULL, ".")) != NULL) {
        int value = atoi(token);

        // Encode the value in base-128 format if needed
        if(value < 128) {
            oid_bytes[i++] = (unsigned char)value;
        } else {
            // Handle larger values (base-128 encoding)
            unsigned char temp[5]; // Max size for base-128 encoding (5 bytes)
            size_t temp_index = 0;

            // Encode value into base-128 (least significant 7 bits first)
            while(value > 0) {
                temp[temp_index++] = (unsigned char)(value & 0x7F);
                value >>= 7;
            }

            // Reverse and add continuation bits for all but the last byte
            for(size_t j = 0; j < temp_index; j++) {
                oid_bytes[i++] = temp[temp_index - 1 - j] | (j == temp_index - 1 ? 0x00 : 0x80);
            }
        }
    }

    // Set the final OID length
    *oid_length = i;
}




int build_snmp_version(char *buffer) {
    buffer[0] = 0x02;
    buffer[1] = 0x01;
    buffer[2] = 0x01;
    return 3;
}

int build_snmp_community(char *buffer) {
    buffer[0] = 0x04;
    buffer[1] = 0x06;
    memcpy(buffer + 2, "public", 6);
    return 8;
}

int build_snmp_request_id(char *buffer, uint32_t request_id) {
    buffer[0] = 0x02;
    buffer[1] = 0x04;
    buffer[2] = (request_id >> 24) & 0xFF;
    buffer[3] = (request_id >> 16) & 0xFF;
    buffer[4] = (request_id >> 8) & 0xFF;
    buffer[5] = request_id & 0xFF;
    return 6;
}

void send_dynamic_snmp_query(const char *oid_string, snmp_context_p *snmp) {
    struct sockaddr_in server_addr;
    unsigned char oid_bytes_system[128];
    size_t oid_length_value;
    char snmp_packet[256];
    int offset = 0;

    oid_to_bytes(oid_string, oid_bytes_system, &oid_length_value);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(161);
    server_addr.sin_addr.s_addr = snmp->ip;

    // Inicio secuencia SNMP
    snmp_packet[offset++] = 0x30;    // Sequence
    int total_length_pos = offset++; // Reservar byte para longitud

    // Version
    offset += build_snmp_version(snmp_packet + offset);

    // Community
    offset += build_snmp_community(snmp_packet + offset);

    // PDU
    snmp_packet[offset++] = 0xa0;  // GetRequest
    int pdu_length_pos = offset++; // Reservar byte para longitud

    // Request ID (4 bytes)
    offset += build_snmp_request_id(snmp_packet + offset, snmp->request_id);

    // Error status
    snmp_packet[offset++] = 0x02;
    snmp_packet[offset++] = 0x01;
    snmp_packet[offset++] = 0x00;

    // Error index
    snmp_packet[offset++] = 0x02;
    snmp_packet[offset++] = 0x01;
    snmp_packet[offset++] = 0x00;

    // Varbind list
    snmp_packet[offset++] = 0x30; // Sequence
    int varbind_list_pos = offset++;

    // Varbind
    snmp_packet[offset++] = 0x30; // Sequence
    int varbind_pos = offset++;

    // OID
    snmp_packet[offset++] = 0x06;
    snmp_packet[offset++] = oid_length_value;
    memcpy(snmp_packet + offset, oid_bytes_system, oid_length_value);
    offset += oid_length_value;

    // NULL value
    snmp_packet[offset++] = 0x05;
    snmp_packet[offset++] = 0x00;

    // Actualizar longitudes
    int varbind_length = (offset - varbind_pos - 1);
    snmp_packet[varbind_pos] = varbind_length;

    int varbind_list_length = (offset - varbind_list_pos - 1);
    snmp_packet[varbind_list_pos] = varbind_list_length;

    int pdu_length = (offset - pdu_length_pos - 1);
    snmp_packet[pdu_length_pos] = pdu_length;

    int total_length = (offset - total_length_pos - 1);
    snmp_packet[total_length_pos] = total_length;

    // Debug print
    /*     printf("PDU length: %d, Varbind list length: %d, Total length: %d\n",
               pdu_length, varbind_list_length, total_length); */

    sendto(snmp->socket, snmp_packet, offset, 0,
           (struct sockaddr *)&server_addr, sizeof(server_addr));
}