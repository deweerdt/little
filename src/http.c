#include "str.h"
#include "http.h"

struct string STR_200 = {
	.str = "HTTP/1.0 200 OK" CRLF CRLF,
	.len = 19,
	.null_terminated = true
};

struct string STR_400 = {
	.str = "HTTP/1.0 400 Bad Request" CRLF CRLF "Bad Request" CRLF CRLF,
	.len = 43,
	.null_terminated = true
};
struct string STR_403 = {
	.str = "HTTP/1.0 403 Forbidden" CRLF CRLF "Forbidden" CRLF CRLF,
	.len = 39,
	.null_terminated = true
};
struct string STR_404 = {
	.str = "HTTP/1.0 404 Not Found" CRLF CRLF "Not Found" CRLF CRLF,
	.len = 39,
	.null_terminated = true
};
struct string STR_500 = {
	.str = "HTTP/1.0 500 Internal Server Error" CRLF CRLF "Internal Server Error" CRLF CRLF,
	.len = 63,
	.null_terminated = true
};
struct string STR_501 = {
	.str = "HTTP/1.0 501 Not Implemented" CRLF CRLF "Not Implemented" CRLF CRLF,
	.len = 51,
	.null_terminated = true
};


