#ifndef  __TRIE_H__
#define  __TRIE_H__

//#include "common.h" // trieVal_t RuleSet
#include <arpa/nameser.h>
#include "list.h"

#define trieVal_t  List* 

#define DEFAULT_VALUE  NULL //0x0
#define MAX_WORD 1024


typedef struct trieNode{
    char key;
    trieVal_t value;
    struct trieNode *next;
    struct trieNode *prev;
    struct trieNode * parent;
    struct trieNode *children;
} trieNode_t;

trieNode_t * TrieInit( );
//trieNode_t *TrieCreateNode( char key, trieVal_t data);
trieNode_t *TrieCreateNode( char key, RRdata *data);
trieNode_t * TrieSearch(trieNode_t * root, const char *key);
trieVal_t * trie_search(trieNode_t * root, const char *key);
void TrieTravel( trieNode_t * tree, char * prefix, int idx, FILE *fp);
void TrieTravelE( trieNode_t * tree, FILE * fp);

void TrieRemove(trieNode_t ** root, char * key);
int TrieLoad(trieNode_t * tree, char * file_name, int rule_no);
//int trie_setall(trieNode_t * tree, trieVal_t set);
void TrieAdd (trieNode_t ** root, char *key, char qtype, RRdata * data);
//void TrieAdd(trieNode_t **root, char *key, char qtype, long timestamp,long ns_ip, long ttl, void *rdata);
void trie_free( trieNode_t * tree);

#define ENDCHAR '\0'
#define WILDCARD '*'

#endif
