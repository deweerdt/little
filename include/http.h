#ifndef _HTTP_H_
#define _HTTP_H_

#include "str.h"

#define CRLF "\r\n"
#define CRLF_LEN 2

#define CRLF_CRLF CRLF CRLF
#define CRLF_CRLF_LEN (CRLF_LEN * 2)

enum http_response_code {
	OK = 200,
	Created = 201,
	Accepted = 202,
	No_Content = 204,
	Moved_Permanently = 301,
	Moved_Temporarily = 302,
	Not_Modified = 304,
	Bad_Request = 400,
	Unauthorized = 401,
	Forbidden = 403,
	Not_Found = 404,
	Internal_Server_Error = 500,
	Not_Implemented = 501,
	Bad_Gateway = 502,
	Service_Unavailable = 503,
};

extern struct string STR_200;
extern struct string STR_400;
extern struct string STR_403;
extern struct string STR_404;
extern struct string STR_500;
extern struct string STR_501;

#endif /* _HTTP_H_ */
