#ifndef _HTTP_H_
#define _HTTP_H_

#define CRLF "\r\n"
#define CRLF_LEN 2

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

static const char STR_200[] = "HTTP/1.0 200 OK" CRLF CRLF;
static const int STR_200_LEN = 19;
static const char STR_400[] = "HTTP/1.0 400 Bad Request" CRLF CRLF;
static const int STR_400_LEN = 28;
static const char STR_403[] = "HTTP/1.0 403 Forbidden" CRLF CRLF;
static const int STR_403_LEN = 26;
static const char STR_404[] = "HTTP/1.0 404 Not Found" CRLF CRLF;
static const int STR_404_LEN = 26;
static const char STR_500[] = "HTTP/1.0 500 Internal Server Error" CRLF CRLF;
static const int STR_500_LEN = 38;
static const char STR_501[] = "HTTP/1.0 501 Not Implemented" CRLF CRLF;
static const int STR_501_LEN = 32;

#endif /* _HTTP_H_ */
