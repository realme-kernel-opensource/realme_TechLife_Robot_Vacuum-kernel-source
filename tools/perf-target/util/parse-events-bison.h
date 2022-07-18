/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_PARSE_EVENTS_UTIL_PARSE_EVENTS_BISON_H_INCLUDED
# define YY_PARSE_EVENTS_UTIL_PARSE_EVENTS_BISON_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int parse_events_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    PE_START_EVENTS = 258,
    PE_START_TERMS = 259,
    PE_VALUE = 260,
    PE_VALUE_SYM_HW = 261,
    PE_VALUE_SYM_SW = 262,
    PE_RAW = 263,
    PE_TERM = 264,
    PE_EVENT_NAME = 265,
    PE_NAME = 266,
    PE_BPF_OBJECT = 267,
    PE_BPF_SOURCE = 268,
    PE_MODIFIER_EVENT = 269,
    PE_MODIFIER_BP = 270,
    PE_NAME_CACHE_TYPE = 271,
    PE_NAME_CACHE_OP_RESULT = 272,
    PE_PREFIX_MEM = 273,
    PE_PREFIX_RAW = 274,
    PE_PREFIX_GROUP = 275,
    PE_ERROR = 276,
    PE_PMU_EVENT_PRE = 277,
    PE_PMU_EVENT_SUF = 278,
    PE_KERNEL_PMU_EVENT = 279,
    PE_ARRAY_ALL = 280,
    PE_ARRAY_RANGE = 281,
    PE_DRV_CFG_TERM = 282
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 95 "util/parse-events.y" /* yacc.c:1909  */

	char *str;
	u64 num;
	struct list_head *head;
	struct parse_events_term *term;
	struct tracepoint_name {
		char *sys;
		char *event;
	} tracepoint_name;
	struct parse_events_array array;

#line 94 "util/parse-events-bison.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif



int parse_events_parse (void *_data, void *scanner);

#endif /* !YY_PARSE_EVENTS_UTIL_PARSE_EVENTS_BISON_H_INCLUDED  */
