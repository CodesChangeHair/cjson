#ifndef LEPTJSON_H__	/* include guard, to prevent multiple inclusions of the same header file, by preprocess */
#define LEPTJSON_H__

/* enum consists of a set of named integer constants. Each name in an enum corresponds to an integer value,starting from 0 by default unless explicitly assigned. */
typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

/* typedef struct lept_value(any name) lept_value
create alias so when we define a new struct, we do not need to struct lept_value X */
/*
JSON最终时一个树状数据结构 目前只需要解析null, true, false
*/
typedef struct {
	double n;	/* store number when type = NUMBER */
	lept_type type;	/* type is enum, a constant integer. For now, we only use it to represent null, true and false. */
}lept_value; 


/* Retruen value 表示解析结果 */
enum {
	LEPT_PARSE_OK = 0,
	LEPT_PARSE_EXPECT_VALUE,
	LEPT_PARSE_INVALID_VALUE,
	LEPT_PARSE_ROOT_NOT_SINGULAR,
	LEPT_PARSE_NUMBER_TOO_BIG
};

/* parse string(null-terminated string) to Json structure
User sent a C string and get a json type data i
提供给外部的API, 用户输入字符串 函数将其解析为JSON树状结构 存储在lept_value中
*/
int lept_parse(lept_value *v, const char *json);

/* get json value type */
lept_type lept_get_type(const lept_value *v);

/* get number when json type is NUMBER */
double lept_get_number(const lept_value *v);

#endif  /* LEPTJSON_H__*/
