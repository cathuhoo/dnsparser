/*****************************************************************************
*                                                                            *
*  -------------------------------- list.c --------------------------------  *
*                                                                            *
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include "list.h"

void list_init(List *list, void (*destroy)(void *data), void (*display)(FILE *fp, void *data), int (*match)( void * key1, void * key2)) 
{

    list->size = 0;
    list->count = 0;
    list->destroy = destroy;
    list->display = display;
    list->match = match;
    list->head = NULL;
    list->tail = NULL;
    return;
}

void list_travel( List * list, FILE * fp)
{
    ListElmt * ptr;
    ptr=list->head;
    while (ptr)
    {
        list->display (fp, ptr->data);
        ptr=ptr->next;
    }
}

void * list_lookup( List * list, void * data)
{
    ListElmt * ptr;
    ptr = list->head;
    while (ptr)
    {
        if ( 1 == list->match(data, ptr->data)) // match
        {
            return ptr->data; 
        }
        else
            ptr = ptr->next;
    }
   return NULL;
}


void list_destroy(List *list) 
{
    void               *data;
    while (list_size(list) > 0) 
    {

       if (list_rem_next(list, NULL, (void **)&data) == 0 && list->destroy != NULL) 
       {
          //  Call a user-defined function to free dynamically allocated data.    
          list->destroy(data);

       }

    }

    //*  No operations are allowed now, but clear the structure as a precaution.   *

    memset(list, 0, sizeof(List));

    return;

}

int list_ins_next(List *list, ListElmt *element, const void *data) 
{

    ListElmt           *new_element;

    //*  Allocate storage for the element.                                         

    if ((new_element = (ListElmt *)malloc(sizeof(ListElmt))) == NULL)
       return -1;

    //*  Insert the element into the list.                                         

    new_element->data = (void *)data;

    if (element == NULL) 
    {

       //*  Handle insertion at the head of the list.                              
       if (list_size(list) == 0)
          list->tail = new_element;

       new_element->next = list->head;
       list->head = new_element;

    }
    else 
    {

       //*  Handle insertion somewhere other than at the head.                     *

       if (element->next == NULL)
          list->tail = new_element;

       new_element->next = element->next;
       element->next = new_element;

    }

    //  Adjust the size of the list to account for the inserted element.          *

    list->size++;

    list->count++;

    return 0;

}

int list_rem_next(List *list, ListElmt *element, void **data) {

    ListElmt           *old_element;

    //  Do not allow removal from an empty list.                                  

    if (list_size(list) == 0)
       return -1;

    //*  Remove the element from the list.                                       
    if (element == NULL) 
    {
       //  Handle removal from the head of the list.                              

       *data = list->head->data;
       old_element = list->head;
       list->head = list->head->next;

       if (list_size(list) == 1)
          list->tail = NULL;

     }
    else 
    {
       //  Handle removal from somewhere other than the head.                     

       if (element->next == NULL)
          return -1;

       *data = element->next->data;
       old_element = element->next;
       element->next = element->next->next;

       if (element->next == NULL)
          list->tail = element;

    }

    //  Free the storage allocated by the abstract data type.                     
    free(old_element);
    //  Adjust the size of the list to account for the removed element.           

    list->size--;

    return 0;
}

void rrdata_print(FILE *fp, void * pp ) // RRdata *p)
{
    char str[1024];

    if (!pp) return ;
    
    RRdata *p = pp;
    fprintf(fp,"|%ld %ld %ld",p->count, p->first_seen, p->last_seen);

    inet_ntop(AF_INET, &p->ns_ip,str, sizeof(str));
    fprintf(fp," %s", str);

    fprintf(fp," %ld %c", p->ttl, TRUE_FALSE(p->authoritative));
    
    switch (p->qtype) {
        case  ns_t_a:
            //memcpy(&ip, p->data, sizeof(long));
            if(NULL == inet_ntop(AF_INET, p->data, str, sizeof(str)))
            {
                fprintf(fp, "IP address Error:");
                break;
            }
            fprintf(fp, " %s", str);
            break;
        default:
            str[0]=0;
            memcpy(str, p->data, p->len);
            str[p->len]=0;
            fprintf(fp, " %s",  str);
            break;
    }
    //fprintf(fp, "\n");
    return;
}
RRdata * rrdata_init(long timestamp, char qtype, long ns_ip, long ttl,int len, void *pdata, char authoritative)
{
    int error =0;
    RRdata *p = malloc(sizeof(RRdata)); 
    if ( p == NULL)
        return NULL;
    p->timestamp = timestamp;
    p->first_seen = timestamp;
    p->last_seen = timestamp;
    p->qtype = qtype;
    p->authoritative=authoritative;
    p->ns_ip = ns_ip;
    p->count = 1;
    p->ttl   = ttl;
    p->len =len;
    switch (qtype) {
        case  ns_t_a:
                p->data=malloc(sizeof(long));
                if( p->data == NULL)
                {
                    error = 1;       
                    break;
                }
                p->len = 4;
                memcpy(p->data, pdata, 4);
        break;
        default : //case ns_t_ns:
                p->data = malloc(len + 1);
                if (p->data == NULL)
                {
                    error=1;
                    break;
                } 
                memcpy(p->data, pdata, len);
                //p->len=len;
        break;
    }

    if (error)
    {
        free(p);
        return NULL;
    }
    return p;
}
int rrdata_match(void *le, void * ne)
{
    RRdata *ple, *pne;
    ple=(RRdata *) le;
    pne=(RRdata *) ne;
    if( ple == NULL || pne == NULL)
        return -1;
    if ( ple->ns_ip != pne->ns_ip) 
    {
        return 0; // different ns_ip 
    }
    if ( ple->len != pne->len)
        return 0;
    if ( 0 != memcmp(ple->data, pne->data, ple->len))
        return 0;
    return 1;
}
int rrdata_merge(List *lp, void *p)
{
    RRdata *ptr, *p2;
    if ( lp == NULL || p == NULL)
        return -1;

    p2=(RRdata*) p;
    ptr=list_lookup(lp, p);
    if(ptr)
    {
        lp->count ++;
        //update *ptr with *p
        ptr->last_seen = p2->timestamp;
        ptr->count ++;
        ptr->ttl = p2->ttl;
        if(p2->authoritative) 
            ptr->authoritative = 1; //TRUE
        rrdata_free(p);
    }
    else
    {
        p2->first_seen=p2->timestamp;
        p2->last_seen=p2->timestamp;
        p2->count =1;
        list_ins_next(lp, NULL, p);
    }
    return 0;
}

//void rrdata_free(RRdata *p)
void rrdata_free(void *p)
{
    if( !p) 
      return ;
   RRdata *pd = p; 
    //fprintf(stdout , "to be freed:\n");
    //rrdata_print(stdout, p);
    if( pd->data)
    {
        free(pd->data);
        pd->data = NULL;
    }
    free(p);
}
/*
int main(int argc, char * argv[])
{
    List *list;
    RRdata *rrd, *rrd1, *rrd2, *rrd3, *rl;
    long ip=1234567;
    char ns_name[]="dns.ccert.edu.cn";
    char ns_name2[]="dns2.ccert.edu.cn";

    if ( NULL == (list = malloc(sizeof(List))))
    {
        return -1;
    }
    
    list_init(list, rrdata_free, rrdata_print, rrdata_match); 
    rrd=rrdata_init(10000, ns_t_a, 54321,2,sizeof(ip), &ip );
    rrd1=rrdata_init(12346, ns_t_ns, 65432,2,strlen(ns_name), ns_name );
    rrd2=rrdata_init(20000, ns_t_a, 54321,2,sizeof(ip), &ip );

    rrd3=rrdata_init(12346, ns_t_ns, 65432,2,strlen(ns_name2), ns_name2 );
    list_ins_next(list, NULL, rrd);
    //list_ins_next(list, NULL, rrd1);
    rrdata_merge(list, rrd1);
    rrdata_merge(list, rrd2);
    rrdata_merge(list, rrd3);
    list_travel(list);
    rl=(RRdata*) list_lookup(list, rrd);
    if (rl)
    {
        printf("found:\n");
        rrdata_print(stdout, rl);
    }
    list_destroy(list);
    free(list);
}
*/
