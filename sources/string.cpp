/****************************************************************************/
/****************************************************************************/

/* 
 * Copyright 2014 Core Security Technologies.
 * 
 * This file is part of Sentinel, an exploit mitigation tool.
 * Sentinel was designed and developed by Nicolas Economou, from the
 *  Exploit Writers team of Core Security Technologies.
 *
 * This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3
 *  as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * For further details, see the file COPYING distributed with Sentinel.
 */

/****************************************************************************/
/****************************************************************************/

/* string.cpp */

/****************************************************************************/
/****************************************************************************/

/* Includes */

#include <string.h>

/****************************************************************************/

/* defines */

#define FALSE 0
#define TRUE  1

/* Para mantener la compatibilidad */
#ifdef _IDA_HPP
  #define strcpy(a,b) qstrncpy(a,b,strlen(b)+1)
  #define strcat(a,b) qstrncat(a,b,strlen(b)+1)
  #define fread(a,b,c,d) qfread(d,a,b)
  #define fwrite(a,b,c,d) qfwrite(d,a,b)
  #define malloc(a) my_malloc(a)
  #define realloc(a,b) my_realloc(a,b)
  #define free(a) my_free(a)
#endif

/****************************************************************************/
/****************************************************************************/

/* Definicion de las clases */

class String
{
private:
  unsigned int len;
  char *string;

public:
  String ();
  ~String ();
  void Reset ( void );
  const char *Get ( void );
  int Set ( const char * );
  unsigned int Len ( void );
  int Append ( char * );
  int Truncate ( unsigned int );

/* Metodos para hacer PERSISTENCIA */
  int Save ( FILE * );
  int Load ( FILE * );
};

/****************************************************************************/
/****************************************************************************/

/* Metodos */

/****************************************************************************/

String::String ()
{
/* Inicializo la longitud */
  this -> len = 0;

/* Inicializo el string */
  this -> string = ( char * ) malloc ( 1 );

  if ( this -> string == NULL )
  {
    printf ( "???\n" );
  }

/* Pongo el EOS */
  *this -> string = '\0';
}

/****************************************************************************/

String::~String ()
{
/* Libero la memoria */
  free ( this -> string );
}

/****************************************************************************/

void String::Reset ( void )
{
/* Reinicializo el contador */
  this -> len = 0;

/* Libero la memoria */
  free ( this -> string );

/* Inicializo el string */
  this -> string = ( char * ) malloc ( 1 );

/* Pongo el EOS */
  *this -> string = '\0';
}

/****************************************************************************/

const char *String::Get ( void )
{
/* Retorno el string */
  return ( this -> string );
}

/****************************************************************************/

int String::Set ( const char *string )
{
  unsigned int len;
  int ret = FALSE;
  char *dest;

/* Reinicializo el string */
  this -> Reset ();

/* Obtengo la longitud del string */
  len = strlen ( string );

/* Reservo la cantidad en bytes de memoria del string a guardar + 1 */
  dest = ( char * ) malloc ( len + 1 );

/* Si todo salio OK */
  if ( dest != NULL )
  {
  /* Seteo la longitud del string */
    this -> len = len;

  /* Seteo el puntero al string */
    this -> string = dest;

  /* Me hago una copia del string */
    strcpy ( this -> string , string );

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

unsigned int String::Len ( void )
{
  return ( this -> len );
}

/****************************************************************************/

int String::Append ( char *string )
{
  unsigned int len;
  char *new_string;
  int ret = FALSE;

/* Obtengo la longitud del string a appendear */
  len = strlen ( string );

/* Intento agrandar el espacio reservado para el string */
  new_string = ( char * ) realloc ( this -> string , this -> len + len + 1 );

/* Si pude agrandar el string */
  if ( new_string != NULL )
  {
  /* Seteo el puntero al nuevo string */
    this -> string = new_string;

  /* Concateno el nuevo string al final del string original */
    strcpy ( this -> string + this -> len , string );

  /* Seteo la nueva longitud del string */
    this -> len = this -> len + len;

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/****************************************************************************/

int String::Truncate ( unsigned int pos )
{
  int ret = FALSE;

/* Si la posicion es valida */
  if ( pos < this -> len )
  {
  /* Seteo el nuevo len del string */
    this -> len = pos;

  /* Realloco el string */
    this -> string = ( char * ) realloc ( this -> string , this -> len + 1 );

  /* Cierro el string */
    this -> string [ pos ] = '\0';

  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret);
}

/****************************************************************************/

int String::Save ( FILE *f )
{
  int ret = TRUE;

/* Guardo las propiedades del objeto */
  fwrite ( this , sizeof ( String ) , 1 , f );

/* Guardo el string */
  fwrite ( this -> string , this -> len + 1 , 1 , f );

  return ( ret );
}

/****************************************************************************/

int String::Load ( FILE *f )
{
  int ret = TRUE;

/* Reseteo el string */
  this -> Reset ();

/* Levanto las propiedades del objeto */
  fread ( this , sizeof ( String ) , 1 , f );

/* Alloco espacio para el string */
  this -> string = ( char * ) malloc ( this -> len + 1 );

/* Levanto el string */
  fread ( this -> string , this -> len + 1 , 1 , f );

  return ( ret );
}

/****************************************************************************/
/****************************************************************************/

#undef malloc
#undef realloc
#undef free

/****************************************************************************/
/****************************************************************************/

