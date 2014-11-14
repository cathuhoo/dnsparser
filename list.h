
#ifndef LIST_H
#define LIST_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

//  Define a structure for linked list elements.                              

typedef struct ListElmt_ {
     void               *data;
     struct ListElmt_   *next;
} ListElmt;

/*****************************************************************************
*                                                                            *
*  Define a structure for linked lists.                                      *
*                                                                            *
*****************************************************************************/

typedef struct List_ {

    int                size;
    long                count; // to record number of access;
                                // increase by 1 on every access
    int                (*match)(const void *key1, const void *key2);
    void               (*destroy)(void *data);
    void               (*display)(FILE * fp, void *data);

    ListElmt           *head;
    ListElmt           *tail;

} List;

/*****************************************************************************
*                                                                            *
*  --------------------------- Public Interface ---------------------------  *
*                                                                            *
*****************************************************************************/

void list_init(List *list, void (*destroy)(void *data), void (*display)(FILE *fp, void *data), int (*match)( void * key1, void * key2));

void list_destroy(List *list);

void * list_lookup( List * list, void * data);

void list_travel( List * list, FILE * fp);

int list_ins_next(List *list, ListElmt *element, const void *data);

int list_rem_next(List *list, ListElmt *element, void **data);

#define list_size(list) ((list)->size)

#define list_head(list) ((list)->head)

#define list_tail(list) ((list)->tail)

#define list_is_head(list, element) ((element) == (list)->head ? 1 : 0)

#define list_is_tail(element) ((element)->next == NULL ? 1 : 0)

#define list_data(element) ((element)->data)

#define list_next(element) ((element)->next)

typedef struct _rr_data{
    long  count;
    long  first_seen;
    long  last_seen;
    char  qtype;
    char  authoritative;
    long  timestamp;
    in_addr_t  ns_ip;
    long  ttl;
    int   len;
    void  *data;
} RRdata;


RRdata * rrdata_init(long timestamp, char qtype, long ns_ip, long ttl, int len, void *pdata, char authoritative);
//free( p->data) and then free(p)
void rrdata_free(void *p);
int rrdata_match(void *le, void * ne);
void rrdata_print(FILE *fp, void *p) ; //RRdata *p);

int rrdata_merge(List *lp, void *p) ; // RRdata *p);

#define TRUE_FALSE(a) (a == 0) ? 'F':'T'
#endif
