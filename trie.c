//#include "common.h"
#include <string.h>
#include "trie.h"
#include "mystring.h"
#include "list.h"
//#define DEFAULT_VALUE  NULL //0x0

void rrlist_printf(FILE *fp, List *lp); 

trieNode_t *TrieCreateNode( char key, RRdata *data)
{
    trieNode_t * node = NULL;
    node = (trieNode_t *) malloc(sizeof(trieNode_t));

    if ( NULL == node )
    {
        printf("Malloca failed\n");
        return node;
    }

    node->key = key;
    node->next = NULL;
    node->children = NULL;
    node->prev = NULL;
    node->parent = NULL;
    //node->value = data;
    if( data != DEFAULT_VALUE)
    {
        node->value = malloc(sizeof(List));
        if ( node->value == NULL)
        {
            printf("Malloca for list failed\n");
            free(node);
            return NULL;
        }
        list_init(node->value, rrdata_free, rrdata_print, rrdata_match); 
        //int list_ins_next(List *list, ListElmt *element, const void *data)
        if( 0> list_ins_next(node->value, NULL, data))
        {
            printf("Insert to list failed\n");
            free(node);
            return NULL;
        }
    }
    else
    {
        node->value = DEFAULT_VALUE;
    }
    return node;
}

trieNode_t * TrieInit( )
{
    //return TrieCreateNode( ENDCHAR, 0xffffffff);
    return TrieCreateNode( ENDCHAR, DEFAULT_VALUE);
}
void TrieAdd(trieNode_t **root, char *key, char qtype, RRdata * pdata) 
{
    trieNode_t * pTrav = NULL, *pFound;

    if( NULL == * root) 
    {
        printf("NULL Tree \n");
        return ;
    }

    pTrav = (*root) -> children;
    
    
    if (NULL != (pFound = TrieSearch(pTrav, key)))
    {
        List *p;
        //pFound->value += rdata ;
        // Add to list
        p = pFound -> value;
        rrdata_merge(p, pdata);
        return ; 
    }

    if(pTrav == NULL )
    {
        /*first node */
        for ( pTrav = * root ; *key; pTrav = pTrav -> children)
        {
            //pTrav -> children = TrieCreateNode ( *key , 0xffffffff);
            pTrav -> children = TrieCreateNode ( *key , DEFAULT_VALUE);
            pTrav -> children->parent = pTrav;
            #ifdef DEBUG
                //printf("\t Inserting: %c \n", pTrav->children->key);
            #endif
            key ++;
        }

        pTrav->children = TrieCreateNode (ENDCHAR, pdata);
        pTrav->children->parent = pTrav;
        return;
    }

    //search in the children chain for prefix
    while ( *key != ENDCHAR )
    {
        if( *key == pTrav->key)
        {
            key ++;
            #ifdef DEBUG
                //printf("\t Traversing child: %c \n", pTrav->children->key);
            #endif
            pTrav = pTrav ->children;
        }
        else
            break;
    }

    //seach the sibling
    while (pTrav -> next) 
    {
        if( *key == pTrav->next->key) //find the matched char, and add it as a new child
        {
            key++;
            TrieAdd( &(pTrav->next), key, qtype, pdata);
            return ;
        }
        //otherwise, continue to the last sibling
        pTrav = pTrav -> next;
    }

    if(*key == ENDCHAR )
        pTrav->next = TrieCreateNode( *key, pdata);
    else 
        pTrav->next = TrieCreateNode( *key, DEFAULT_VALUE);

    //pTrav->next = TrieCreateNode( *key, pdata);
    //TODO: check this piece of code carefully later.
    //Problems might still exist for substring insertion.
    //If you insert a substring of an existing node,
    //it will create a duplicated node
    pTrav->next->parent = pTrav->parent;
    pTrav->next->prev = pTrav;

    #ifdef DEBUG
        //printf("\t Inserting %c as neighbour of %c \n", pTrav->next->key,pTrav->key);
    #endif

    if (*key == ENDCHAR) 
        return;

    key++;

    //Now create a new chain for the rest of string 
    for(pTrav = pTrav->next; *key; pTrav = pTrav->children)
    {
        //pTrav->children = TrieCreateNode(*key, 0xffffffff);
        pTrav->children = TrieCreateNode(*key, DEFAULT_VALUE);
        pTrav->children->parent = pTrav;
        #ifdef DEBUG
            //printf("\t Inserting: %c \n", pTrav->children->key);
        #endif
        key++;
    }

    pTrav->children = TrieCreateNode(ENDCHAR, pdata);
    pTrav->children->parent = pTrav;
    #ifdef DEBUG
        //printf("\t Inserting: %c\n",pTrav->children->key);
    #endif
    return;
}

// search reverse of key, from trie root
trieVal_t * trie_search(trieNode_t * root, const char *key)
{
    trieNode_t * pt = NULL;
    char str_r[MAX_WORD], str_trim[MAX_WORD];

    if ( root == NULL || key == NULL)
        return NULL;

    strtrim2(str_trim, MAX_WORD, key);

    strReverse(str_trim, str_r);

    pt = TrieSearch(root->children, str_r);

    if (pt)
    {
        //fprintf(stdout, "pt:%lx\n", pt);
        //fprintf(stdout, "*pt->value:%lx\n", pt->value);
        return &pt->value;
    }
    /*
    else
    {
        pt = TrieSearch(root->children, "*");
        if (pt)
            return &pt->value;
    }
    */
    return NULL;
    
}
//search from the children of trie root
trieNode_t* TrieSearch(trieNode_t *root, const char *key)
{
    trieNode_t *level = root;
    trieNode_t *pPtr = NULL;

    int lvl = 0;
    while(1)
    {
        trieNode_t * found = NULL;
        trieNode_t * curr;

        for ( curr = level ; curr != NULL; curr = curr->next )
        {
            if( curr->key == *key)
            {
                found = curr;
                lvl ++;
                break;
            }
        }

        if (found == NULL )
            return NULL;
        
        if( *key == ENDCHAR )
        {
            pPtr = curr;
            return pPtr;
        }

        level = found -> children ;
        key ++;
    } //while
}

void TrieTravelE( trieNode_t * tree, FILE *fp)
{
    char buffer[MAX_WORD];
    int index=0;

    if (tree == NULL) 
        return;

    memset(buffer, 0, sizeof(buffer));
    TrieTravel(tree->children, buffer, index, fp);

}
void rrlist_printf(FILE *fp, List *lp)
{
    list_travel(lp, fp); 
    return; 
}
void rrlist_free(List *lp)
{

}
void TrieTravel( trieNode_t * tree, char * prefix, int idx, FILE * fp)
{

    if( tree  == NULL)
        return ; 

    if ( tree-> key != ENDCHAR)
    {
        *(prefix + idx)  = tree->key; 
        //printf("%s%c", tree->key);
    }
    else 
    {
	    char outStr[MAX_WORD];
        char *ptr;
        char qt;
        *(prefix + idx)  = ENDCHAR; 

        outStr[0]=0;
	    strReverse(prefix, outStr);
        ptr=outStr+1; 
        qt=*outStr; 
        fprintf(fp, "%s %d", ptr, qt ); //, tree->value);
        if( tree->value )
        {
            fprintf(fp, " %d %ld", tree->value->size, tree->value->count); 
            list_travel( tree->value, fp);
        }
        fprintf(fp, "\n");
        //fprintf(fp, "%s %ld\n",  ptr, tree->value);
        //total += 1;
    }

    if ( tree->children)
        TrieTravel( tree->children, prefix, idx+1 , fp);
    if ( tree->next)
        TrieTravel( tree->next, prefix,idx, fp);

}
void trie_free( trieNode_t * tree)
{

    if( tree  == NULL)
        return ; 

    if ( tree->children)
        trie_free( tree->children); 
    if ( tree->next)
        trie_free( tree->next);

    if(tree->parent)
        tree->parent->children = NULL; 
    if(tree->prev)
        tree->prev->next = NULL; 

    if(tree->value)
    {
        list_destroy( tree->value);
        free(tree->value);
        tree->value = NULL;
    }
    free(tree);
}
/*
int trie_setall(trieNode_t * tree, RuleSet set)
{
    if( tree  == NULL)
        return 0 ; 

    if ( tree-> key == ENDCHAR)
    {
        tree->value |= set;
    }

    if ( tree->children)
        trie_setall( tree->children, set);
    if ( tree->next)
        trie_setall( tree->next, set);
    return 0;
}
*/

/* This function has not been tested */
void TrieRemove(trieNode_t ** root, char * key)
{
    trieNode_t * tPtr = NULL;
    trieNode_t * tmp  = NULL;

    if( NULL == * root || NULL == key)
        return ;
    
    tPtr = TrieSearch( (*root)->children, key);
    
    if( NULL == tPtr)
    {
        printf("Key not found in the trie \n");
        return ;
    }

    while(1)
    {
        //if (tPtr->parent)
            
        if( tPtr->prev && tPtr->next )
        {
            tmp = tPtr;
            tPtr->next->prev = tPtr->prev;
            tPtr->prev->next = tPtr->next;
            free(tmp);
            break;
        }
        else if ( tPtr->prev && !(tPtr->next))
        {
            tmp = tPtr;
            tPtr->prev->next = NULL;
            free(tmp);
            break;
        }
        else if (!(tPtr->prev) && tPtr->next)
        {
            tmp = tPtr;
            tPtr->parent->children = tPtr->next;
            free(tmp);
            break;
        }
        else // prev == NUL && next == NULL
        {
            tmp=tPtr;
            tPtr = tPtr->parent;
            free(tmp);
           
        }
    }

}
int TrieLoad(trieNode_t * tree, char * file_name, int rule_no)
{
    char line[MAX_WORD];
    char * str; 
    FILE * fp;
    char r_name[MAX_WORD];
    char r_name_t[MAX_WORD];
    //RuleSet set;
    long total=0, i=0;


    if ( (fp=fopen(file_name, "r") )==NULL)
    {
        printf("ERROR on open file :%s \n", file_name);
        return -1;
    }
    //printf("Loading %s \n", file_name);
    while( fgets(line, MAX_WORD, fp) != NULL )
    {
        char *ptimes, *token, *qname;
        //long qtimes;
        int length,len;
        char qtype;
        long timestamp,ns_ip, ttl;
        char *rdata;
        
        
        total ++;
        //set = 0x0;
        str=strtrim(line);
        length=strlen(str);

    //#r_name, qtype, timestamp, ns_ip, ttl , rdata
    //#www.google.com 1 20140104 202.112.50.2 300 166.111.111.11
    //#google.com 2 20140104  1234  3600  4321
        
        if (str[0] == '\0' || str[0] =='#' || str[0] == ';')
            continue;
        ptimes=str;

        if ((token=strsep(&ptimes, " ")) != NULL)
        {
           qname=token;        
        }
        else 
            continue;

        if ((token=strsep(&ptimes, " ")) != NULL)
        {
           qtype=strtol(token, NULL, 10);        
        }
        else 
            continue;

        if ((token=strsep(&ptimes, " ")) != NULL)
        {
           timestamp=strtol(token, NULL, 10);        
        }
        else 
            continue;

        if ((token=strsep(&ptimes, " ")) != NULL)
        {
           ns_ip=strtol(token, NULL, 10);        
        }
        else 
            continue;
        if ((token=strsep(&ptimes, " ")) != NULL)
        {
           ttl=strtol(token, NULL, 10);        
        }
        else 
            continue;

        if ((token=strsep(&ptimes, " ")) != NULL)
        {
            if(qtype == ns_t_a)
            {
                len =4;
                long ip; 
                ip = strtol(token, NULL, 10);         
                memcpy(token, &ip, sizeof(ip));
                rdata = token;
            }
            else
            {
                rdata= token ;//strtol(token, NULL, 10);        
                len =strlen(rdata);
            }
        }
        else 
            continue;
        //#r_name, qtype, timestamp, ns_ip, ttl , rdata
        fprintf(stdout, "%s %ld %ld %d %ld %s\n",
                qname, timestamp, ns_ip, qtype, ttl, rdata);
        RRdata *pdata = rrdata_init(timestamp, qtype, ns_ip, ttl, len, rdata, 1);
        //continue ; 
/*
        while (*ptimes !=' ' && ptimes < str + length) 
            ptimes++;
        if ( *ptimes == ' ')
        {
            *ptimes = 0;
            ptimes ++;
            qtimes=strtol(ptimes,NULL, 10);  
        }
        else
            qtimes=1;
 */       
        //set = 1<< rule_no;
        //set = qtimes ; //1<< rule_no;

        r_name_t[0] = qtype; //ns_t_a;
        r_name_t[1] = 0; 
        strcat(r_name_t, str);

        strReverse(r_name_t, r_name);
        //strReverse(str, r_name);
        i++;
        //TrieAdd(&tree, r_name, qtimes); 
        TrieAdd(&tree, r_name, qtype, pdata);

    }
    fprintf(stderr, "Total Added %ld, total lines:%ld \n", i, total);
    fclose(fp);

    return 0;
}

/*
// To test the code related to trie
//
int main ( int argc , char * argv[])
{
    trieNode_t *tree;
    trieNode_t *srch; 
    char * str, tmpStr[MAX_WORD], str_r[MAX_WORD];
    int i;

    //tree = TrieCreateNode( ENDCHAR, 0xffffffff);
    if( argc < 3)
    {
        printf("Usage:./%s <domain_file> <out_file>\n", argv[0]);
        exit(-1);
    } 

    FILE * fout= fopen(argv[2], "w");

    if (fout == NULL)
    {
        printf("Cannot open file: %s to write\n", argv[2]);
        exit(-1);
    }
    trieNode_t * tree_ip; //, *tree_domain;
    tree_ip = TrieInit();
    printf("Loading domain: %s ...\n", argv[1]);
    TrieLoad( tree_ip, argv[1], 1);

    //printf("Loaded, press any key to Travel:\n");
    //getchar();
    TrieTravelE(tree_ip, fout);

    for ( i=3; i < argc ; i++) 
    {
        str = argv[i];
        strReverse(str, str_r);
        srch = TrieSearch ( tree_ip->children, str_r);
        //srch = TrieSearch ( tree, str);
        if (srch == NULL)
        {
            printf("%s not found \n", str);
        }
        else
        {
            printf("%s found, value:%ld \n", str, srch->value);
        }
    }

    printf("Traveling done, press any key to free trie:\n");
    getchar();
   
    trie_free( tree_ip);
    fclose(fout);

    printf("press any key to quit:\n");
    getchar();
   

    return 0;
}

*/
