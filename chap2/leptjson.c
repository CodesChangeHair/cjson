#include "leptjson.h"
#include <assert.h>	/* assert() */
#include <stdlib.h>	/* NULL    */
#include <errno.h>  /* errno */
#include <math.h>	/* HUGE_VAL */

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json ++; } while(0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')

/* 为减少解析函数之间传递多个参数 我们把需要传递的数据都放进结构体lept_context */
typedef struct {
	const char *json;
}lept_context;

/* JSON-text = ws value ws 
 ws 表示空格 lept_parse_whitespace()跳过空格 */
static void lept_parse_whitespace(lept_context *c) {
	const char *p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		++ p;
	c->json = p;
}

#if 0 
static int lept_parse_null(lept_context *c, lept_value *v) {
	/* 查看当前4个字符是否依次为null */
	EXPECT(c, 'n');
	/* 因为\0 ！= null中的任意字符 并且||具有短路特性 所以不会越界 */
	if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 3;
	v->type = LEPT_NULL;
	return LEPT_PARSE_OK;
}
static int lept_parse_true(lept_context *c, lept_value *v) {
	EXPECT(c, 't');
	if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 3;
	v->type = LEPT_TRUE;
	return LEPT_PARSE_OK;
}

static int lept_parse_false(lept_context *c, lept_value *v) {
	EXPECT(c, 'f');
	if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 4;
	v->type = LEPT_FALSE;
	return LEPT_PARSE_OK;
}
#endif

static int lept_parse_literal(lept_context *c, lept_value *v, const char *literal, lept_type type) {
	size_t i;
	
	EXPECT(c, *literal);
	++ literal;
	for (i = 0; literal[i]; ++ i) {
		if (c->json[i] != literal[i])
			return LEPT_PARSE_INVALID_VALUE;
	}
	c->json += i;
	v->type = type;
	return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context *c, lept_value *v) {
	char *end;
	/* validate number */
	const char *p = c->json;
	/* if negative, skip one char*/
	if (*p == '-')	
		++ p;
	/* integer */
	if (*p == '0') ++ p;
	else {
		if (!ISDIGIT(*p))	return LEPT_PARSE_INVALID_VALUE;
		++ p;
		while (ISDIGIT(*p))	++ p;
	}
	
	if (*p == '.') {
		++ p;
		if (ISDIGIT(*p))		
			while (ISDIGIT(*p))	++ p;	/* skip over all digit */
		else	/* there must be digit after '.' */
			return LEPT_PARSE_INVALID_VALUE;
	}	

	if (*p == 'E' || *p == 'e') {
		++ p;
		if (*p == '+' || *p == '-')
			++ p;
		if (!ISDIGIT(*p))	return LEPT_PARSE_INVALID_VALUE;
		while (ISDIGIT(*p))	++ p;
	}
	/* double strtod(const char *str, char **endptr): string to double,
		str: a pointer to string 
		endptr: a pointer to a pointer of type char, which will be set to the
			position of the first character that was not part of the number.
	  */	
	v->n = strtod(c->json, &end);
	
	if (errno == ERANGE) {
		errno = 0;
		if (v->n == HUGE_VAL || -v->n == HUGE_VAL)
			return LEPT_PARSE_NUMBER_TOO_BIG;
	}
	
	c->json = p;
	v->type = LEPT_NUMBER;
	return LEPT_PARSE_OK;	
}

static int lept_parse_value(lept_context *c, lept_value *v) {
	/* 根据第一个非空字符判断JSON的type */
	switch (*c->json) {
		case 'n': 	return lept_parse_literal(c, v, "null", LEPT_NULL);		/* null */
		case 't': 	return lept_parse_literal(c, v, "true", LEPT_TRUE);		/* true */
		case 'f':	return lept_parse_literal(c, v, "false", LEPT_FALSE);
		default:	return lept_parse_number(c, v);	/* let parse_number test if there are invalid value */
		case '\0':  return LEPT_PARSE_EXPECT_VALUE;		/* no value */
	}
}

/* 非static 允许外部访问 作为接口 */
int lept_parse(lept_value *v, const char *json) {
	lept_context c;
	int ret;
	assert(v != NULL);
	c.json = json;
	v->type = LEPT_NULL;
	lept_parse_whitespace(&c);
	ret = lept_parse_value(&c, v);
	if (ret != LEPT_PARSE_OK)
		return ret;
	lept_parse_whitespace(&c);
	if (*c.json) {
		v->type = LEPT_NULL;
		return LEPT_PARSE_ROOT_NOT_SINGULAR;
	}
	return LEPT_PARSE_OK;
}

lept_type lept_get_type(const lept_value *v) {
	assert(v != NULL);
	return v->type;
}

double lept_get_number(const lept_value *v) {
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->n;
}
