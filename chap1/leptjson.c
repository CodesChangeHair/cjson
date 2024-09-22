#include "leptjson.h"
#include <assert.h>	/* assert() */
#include <stdlib.h>	/* NULL    */

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json ++; } while(0)

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

static int lept_parse_value(lept_context *c, lept_value *v) {
	/* 根据第一个非空字符判断JSON的type */
	switch (*c->json) {
		case 'n': 	return lept_parse_null(c, v);		/* null */
		case 't': 	return lept_parse_true(c, v);		/* true */
		case 'f':	return lept_parse_false(c, v);
		case '\0':  return LEPT_PARSE_EXPECT_VALUE;		/* no value */
		default:	return LEPT_PARSE_INVALID_VALUE;	/* invalid value 异常值 */
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
	if (*c.json)
		return LEPT_PARSE_ROOT_NOT_SINGULAR;
	return LEPT_PARSE_OK;
}

lept_type lept_get_type(const lept_value *v) {
	assert(v != NULL);
	return v->type;
}


