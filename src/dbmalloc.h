#ifndef DBMALLOC_H_
#define DBMALLOC_H_

#include "options.h"
#include "dbhelpers.h"
#include <stdint.h>
#include <stdlib.h>

void * m_malloc(size_t size);
void * m_calloc(size_t nmemb, size_t size);
void * m_strdup(const char * str);
void * m_realloc(void* ptr, size_t size);
void * m_asprintf(const char * fmt, ...) ATTRIB_PRINTF(1, 2);

#if DROPBEAR_TRACKING_MALLOC
void m_free_direct(void* ptr);
void m_malloc_set_epoch(unsigned int epoch);
void m_malloc_free_epoch(unsigned int epoch, int dofree);

#else
/* plain wrapper */
#define m_free_direct	free
#define m_free		free

#endif



#endif /* DBMALLOC_H_ */
