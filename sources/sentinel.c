/***************************************************************************/

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

/***************************************************************************/

/* Sentinel.c */

/***************************************************************************/

#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <winsock2.h>

/***************************************************************************/

#define SYMFLAG_EXPORT 0x200

/***************************************************************************/

typedef struct
{
  void *protected_function;
  unsigned int base_pointer;
  unsigned int stack_pointer;
  unsigned int return_address;
} Entry;

typedef struct
{
  unsigned long int edi;
  unsigned long int esi;
  unsigned long int ebp;
  unsigned long int esp;
  unsigned long int ebx;
  unsigned long int edx;
  unsigned long int ecx;
  unsigned long int eax;
} Register;

/***************************************************************************/

void main ( void );
__declspec ( naked ) void _pusher ( void );
void pusher ( void * , unsigned int * , Register * );
__declspec ( naked ) void _poper ( void );
void poper ( void * , unsigned int * , Register * );

void stack_allocator ( void );
void *get_teb_address ( void );

void stack_caller_detected ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
void stack_pivoting_detected ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
void stack_unusual_activity ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
void stack_pointer_modified ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
void base_pointer_modified ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
void base_pointer_unusual_activity ( void * , unsigned int , unsigned int , unsigned int , unsigned int , unsigned int );
void return_address_modified ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
void bad_caller_detected ( void * , unsigned int , unsigned int , unsigned int , unsigned int );
int is_bad_caller ( unsigned char * );

char *generate_message ( char * , char * , void * , unsigned int , unsigned int , unsigned int , unsigned int , char * );
int alert_message ( char * , char * );

/* Funciones para comunicarme con la GUI */
//int send_command ( HANDLE , unsigned int , unsigned int , unsigned char * );
int send_command ( SOCKET , unsigned int , unsigned int , unsigned char * );
//int recv_command ( HANDLE , unsigned int * , unsigned int * , unsigned char * );
int recv_command ( SOCKET , unsigned int * , unsigned int * , unsigned char * );

/* Funciones para el manejo del proceso */
int SuspendAllMyThreads ( int );
int ActivateAllMyThreads ( int );
int GetThreadIds ( int , int * );
int mySuspendThread ( int );
int myActivateThread ( int );
int GetMyProcessName ( int , char * );
int GetModuleNameByAddress ( int , void * , char * );
int GetFunctionNameByAddress ( int , char * , unsigned int , char * );
int GetModuleLimitsByAddress ( int , unsigned int , unsigned int * , unsigned int * );

/***************************************************************************/

/* Bufferes para NO usar el STACK */

//HANDLE sentinel_server;
SOCKET sentinel_server;
int pid;

/***************************************************************************/

BOOL APIENTRY DllMain ( HMODULE Module, DWORD Reason, LPVOID Reserved )
{
/* Si se esta cargando */
  if ( Reason == 1 )
  {
  /* Inicializo a Sentinel */
    main ();
  }

  return ( TRUE );
}

/***************************************************************************/

LONG WINAPI f ( EXCEPTION_POINTERS *excepcion )
{
  static int times = 1;
//  int ret = EXCEPTION_EXECUTE_HANDLER;
  int ret = EXCEPTION_CONTINUE_SEARCH;

/* Si es un breakpoint */
  if ( excepcion -> ExceptionRecord -> ExceptionCode == EXCEPTION_BREAKPOINT )
  {
  /* Si es la segunda vez */
    if ( times % 2 == 0 )
    {
      ret = EXCEPTION_CONTINUE_EXECUTION;

    /* Muevo EIP a la proxima instruccion */
//    excepcion -> ContextRecord -> Eip = lala;
//    excepcion -> ContextRecord -> Eip = 0x90909090;
//    excepcion -> ExceptionRecord -> ContextRecord -> Eip = lala;
      excepcion -> ContextRecord -> Eip += 1;
//    excepcion -> ContextRecord -> Esp += 0x20;
    }

    times ++;
  }

/* Hago que intente de nuevo */
//  return ( EXCEPTION_CONTINUE_EXECUTION );
//  return ( 0 );
//  return ( EXCEPTION_CONTINUE_SEARCH );
  return ( ret );
}

/****************************************************************************/

void main ( void )
{
  unsigned char **sentinel_pipe_str;
  unsigned int operation_id;
  unsigned int operation_size;
//  unsigned int *p = 0x20ff0;
  unsigned int sentinel_port;
  int protection_activated = FALSE;
  char buffer [ 256 ];
  char *sentinel_pipe;

/* Obtengo el puerto TCP donde esta escuchando la GUI */
  sentinel_port = * ( unsigned int * ) ( ( unsigned int ) get_teb_address () + 0xffc );

/* Limpio el puntero */
  * ( unsigned int * ) ( ( unsigned int ) get_teb_address () + 0xffc ) = NULL;

/* Me conecto a Sentinel-GUI */
//  sentinel_server = CreateFile ( sentinel_pipe , GENERIC_READ | GENERIC_WRITE , 0 , NULL , OPEN_EXISTING , 0 , NULL );

/* Si me pude conectar a la GUI */
  if ( connect_to_gui ( "127.0.0.1" , sentinel_port , &sentinel_server ) == TRUE )
  {
  /* Obtengo mi PID */
    pid = GetCurrentProcessId ();

  /* Le paso los datos que necesita Sentinel-GUI */
    * ( unsigned int * ) &buffer [ 0x0 ] = pid;
    * ( unsigned int * ) &buffer [ 0x4 ] = ( unsigned int ) GetCurrentThreadId ();
    * ( unsigned int * ) &buffer [ 0x8 ] = ( unsigned int ) _pusher;
    * ( unsigned int * ) &buffer [ 0xc ] = ( unsigned int ) _poper;
    * ( unsigned int * ) &buffer [ 0x10 ] = ( unsigned int ) &protection_activated;

  /* Marco al THREAD para que los chequeos NO actuen */
    asm mov dword ptr fs:[0xff8],1

  /* Suspendo TODOS los threads */
    SuspendAllMyThreads ( pid );

  /* Le digo a la GUI que me proteja */
    send_command ( sentinel_server , 0x80000001 , sizeof ( unsigned int ) * 5 , buffer );

  /* Recibo el OK */
    recv_command ( sentinel_server , &operation_id , &operation_size , buffer );

  /* Espero que la GUI me de el OK */
    while ( protection_activated == FALSE );

  /* Restauro TODOS los threads */
    ActivateAllMyThreads ( pid );

  /* Seteo el exception handler */
//    SetUnhandledExceptionFilter ( ( LPTOP_LEVEL_EXCEPTION_FILTER ) f );

  /* Breakpoint para disparar el debugger */
//    asm int 3

  /* Armo la linea de ejecucion */
//    sprintf ( cmd , "e:\\bcc32\\protector.exe %i %x %x bug.exe" , GetCurrentProcessId ()  , _pusher , _poper );

  /* Ejecuto el protector */
//    system ( cmd );
  }
}

/***************************************************************************/

__declspec ( naked ) void _pusher ( void )
{
/* Salvo los EFLAGS */
  asm pushfd

/* Si estoy haciendo llamados desde Sentinel */
  asm cmp dword ptr fs:[0xff8],1
  asm je pusher_exit

/* Breakpoint */
//  asm int 3

/* Si tengo un STACK para el CHECKER */
  asm cmp dword ptr fs:[0xff0],0
  asm jne seguir1

/* Alloco STACK para este thread */
  asm pushad
  asm call stack_allocator
  asm popad

/* Continuo con los chequeos */
  seguir1:

/* Hago un STACK SWITCH */ 
  asm mov dword ptr fs:[ 0xff4 ],esp
  asm mov esp,dword ptr fs:[ 0xff0 ]
//  asm add esp,0x4000
  asm add esp,0x10000

/* Salvo todos los registros */
  asm pushad

/* Realizo los chequeos */
  asm lea eax,[esp]
  asm push eax
  asm mov eax, dword ptr fs:[ 0xff4 ]
  asm mov ebx, [eax+0x08]
  asm add eax,0xc
  asm push eax
  asm push ebx
  asm call pusher
  asm add esp,0x0c

/* Restauro todos los registros */
  asm popad

/* Restauro el STACK POINTER */
  asm mov esp, dword ptr fs:[0xff4]

/* Salgo */
  pusher_exit:

/* Restauro los EFLAGS */
  asm popfd

/* Retorno al STUB */
  asm ret
}

/***************************************************************************/

__declspec ( naked ) void _poper ( void )
{
/* Salvo los EFLAGS */
  asm pushfd

/* Si estoy haciendo llamados desde Sentinel */
  asm cmp dword ptr fs:[0xff8],1
  asm je poper_exit

/* Breakpoint */
//  asm int 3

/* Si tengo un STACK para el CHECKER */
  asm cmp dword ptr fs:[0xff0],0
  asm jne seguir2

/* Alloco STACK para este thread */
  asm pushad
  asm call stack_allocator
  asm popad

/* Continuo con los chequeos */
  seguir2:

/* Hago un STACK SWITCH */ 
  asm mov dword ptr fs:[ 0xff4 ],esp
  asm mov esp,dword ptr fs:[ 0xff0 ]
//  asm add esp,0x4000
  asm add esp,0x10000

/* Salvo todos los registros */
  asm pushad

/* Realizo los chequeos */
  asm lea eax,[esp]
  asm push eax
  asm mov eax, dword ptr fs:[ 0xff4 ]
  asm mov ebx, [eax+0x08]
  asm add eax,0xc
  asm push eax
  asm push ebx
  asm call poper
  asm add esp,0x0c

/* Restauro todos los registros */
  asm popad

/* Restauro el STACK POINTER */
  asm mov esp, dword ptr fs:[0xff4]

/* Salgo */
  poper_exit:

/* Restauro los EFLAGS */
  asm popfd

/* Retorno al STUB */
  asm ret
}

/***************************************************************************/

void pusher ( void *protected_function , unsigned int *stack , Register *registers )
{
//  unsigned int *log_counter = 0x20ffc;
  unsigned int return_address;
  unsigned int stack_base;
  unsigned int stack_limit;
  unsigned int *TEB;
  unsigned int oldp;
  int operation_flag;
  Entry *logpage;

///////////////////////

/* Obtengo la direccion de la TEB */
  TEB = ( unsigned int * ) get_teb_address ();

/* Flag para saber si estoy haciendo llamados a funciones desde Sentinel */
  operation_flag = TEB [ 0xff8 / 4 ];

/* Si estoy llamando a alguna API desde Sentinel */
  if ( operation_flag == TRUE )
  {
  /* No hago ningun chequeo */
    return;
  }

///////////////////////

/* Obtengo el puntero a la pagina de memoria donde LOGUEO */
  logpage = ( Entry * ) TEB [ 0xffc / 4 ];

/* Obtengo los RANGOS VALIDOS del STACK */
  stack_base = TEB [ 0x8 / 4 ];
  stack_limit = TEB [ 0x4 / 4 ];

/* Si es la primera vez */
  if ( logpage == NULL )
  {
  /* Marco al FLAG para SABER que estoy llamando a APIs */
    TEB [ 0xff8 / 4 ] = TRUE;

  /* Marco al STACK como NO ejecutable */
    VirtualProtect ( ( void * ) stack_base , stack_limit - stack_base , PAGE_READWRITE , &oldp );

  /* Alloco una pagina de memoria para LOGUEAR */
    logpage = VirtualAlloc ( NULL , 0x1000 , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );

  /* Me posiciono al final de la pagina */
    logpage = ( Entry * ) ( ( unsigned int ) logpage + 0x1000 );

  /* Desmarco el flag */
    TEB [ 0xff8 / 4 ] = FALSE;
  }

///////////////////////

/* Incremento el contador de logueos */
//  ( *log_counter ) ++;

//  if ( *log_counter == 0x1b3 )
//  {
//    while ( 1 );
//    asm int 3
//  }

///////////////////////

/* Return address */
  return_address = *stack;

/* Si el CALL fue hecho desde el STACK */
  if ( ( stack_base <= return_address ) && ( return_address < stack_limit ) )
  {
  /* Si tengo alguna pareja LOGUEADA */
    if ( ( unsigned int ) logpage & 0xfff )
    {
    /* Stack caller detected */
      stack_caller_detected ( protected_function , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
    }
    else
    {
    /* Stack caller detected */
      stack_caller_detected ( protected_function , ( unsigned int ) stack , return_address , 0 , 0 );
    }
  }

/* Si el STACK POINTER esta fuera de RANGO ( STACK PIVOTING ! ) */
  if ( stack < stack_base || stack_limit <= stack )
  {
//    asm int 3

  /* Si tengo alguna pareja LOGUEADA */
    if ( ( unsigned int ) logpage & 0xfff )
    {
    /* Stack pivoting detected */
      stack_pivoting_detected ( protected_function , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
    }
    else
    {
    /* Stack pivoting detected */
      stack_pivoting_detected ( protected_function , ( unsigned int ) stack , return_address , 0 , 0 );
    }
  }

///* Si tengo alguna pareja LOGUEADA */
//  if ( ( unsigned int ) logpage & 0xfff )
//  {
//  /* Si el CURRENT STACK POINTER no crecio con respecto al ANTERIOR */
//    if ( ! ( stack < logpage -> stack_pointer ) )
//    {
//    /* Stack unusual activity */
//      stack_unusual_activity ( protected_function , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
//    }
//  }

/* Si es una funcion CRITICA !!! */
/* Si el BASE POINTER esta fuera del STACK */
//  if ( registers -> ebp < stack_base || stack_limit <= registers -> ebp )
//  {
//  /* Stack unusual activity */
//    base_pointer_unusual_activity ( protected_function , registers -> ebp , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
//  }

/* Si la instruccion anterior a la que hay que RETORNAR NO es un CALL */
  if ( is_bad_caller ( ( unsigned char * ) *stack ) == TRUE )
  {
  /* Si tengo alguna pareja LOGUEADA */
    if ( ( unsigned int ) logpage & 0xfff )
    {
    /* Invalid CALL detected */
      bad_caller_detected  ( protected_function , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
    }
    else
    {
    /* Invalid CALL detected */
      bad_caller_detected  ( protected_function , ( unsigned int ) stack , return_address , 0 , 0 );
    }
  }

///////////////////////

/* Apunto a la proxima dupla */
  logpage --;

/* Salvo los valores */
  logpage -> protected_function = protected_function;
  logpage -> base_pointer = registers -> ebp;
  logpage -> stack_pointer = stack;
  logpage -> return_address = *stack;

/* Actualizo el puntero en la TEB */
  TEB [ 0xffc / 4 ] = ( unsigned int ) logpage;
}

/***************************************************************************/

void poper ( void *reporter_address , unsigned int *stack , Register *registers )
{
  unsigned int return_address;
  unsigned int stack_base;
  unsigned int stack_limit;
  unsigned int *TEB;
  int operation_flag;
  int continue_check = TRUE;
  int oldp;
  Entry *logpage;
  Entry *logpage2;

///////////////////////

/* Obtengo la direccion de la TEB */
  TEB = ( unsigned int * ) get_teb_address ();

/* Flag para saber si estoy haciendo llamados a funciones desde Sentinel */
  operation_flag = TEB [ 0xff8 / 4 ];

/* Si estoy llamando a alguna API desde Sentinel */
  if ( operation_flag == TRUE )
  {
  /* No hago ningun chequeo */
    return;
  }

///////////////////////

/* Return address */
  return_address = *stack;

/* Obtengo los RANGOS VALIDOS del STACK */
  stack_base = TEB [ 0x8 / 4 ];
  stack_limit = TEB [ 0x4 / 4 ];

/* Obtengo el puntero a la pagina de memoria donde LOGUEO */
  logpage = ( Entry * ) TEB [ 0xffc / 4 ];

/* Si es la primera vez */
  if ( logpage == NULL )
  {
  /* Marco al FLAG para SABER que estoy llamando a APIs */
    TEB [ 0xff8 / 4 ] = TRUE;

  /* Marco al STACK como NO ejecutable */
    VirtualProtect ( ( void * ) stack_base , stack_limit - stack_base , PAGE_READWRITE , &oldp );

  /* Alloco una pagina de memoria para LOGUEAR */
    logpage = VirtualAlloc ( NULL , 0x1000 , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );

  /* Me posiciono al final de la pagina */
    logpage = ( Entry * ) ( ( unsigned int ) logpage + 0x1000 );

  /* Desmarco el flag */
    TEB [ 0xff8 / 4 ] = FALSE;
  }

///////////////////////

/* Si el CALL fue hecho desde el STACK */
  if ( ( stack_base <= return_address ) && ( return_address < stack_limit ) )
  {
  /* Si tengo alguna pareja LOGUEADA */
    if ( ( unsigned int ) logpage & 0xfff )
    {
    /* Stack caller detected */
      stack_caller_detected ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
    }
    else
    {
    /* Stack caller detected */
      stack_caller_detected ( reporter_address , ( unsigned int ) stack , return_address , 0 , 0 );
    }
  }

/* Si el STACK POINTER esta fuera de RANGO ( STACK PIVOTING ! ) */
  if ( stack < stack_base || stack_limit <= stack )
  {
  /* Si tengo alguna pareja LOGUEADA */
    if ( ( unsigned int ) logpage & 0xfff )
    {
    /* Stack pivoting detected */
      stack_pivoting_detected ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
    }
    else
    {
    /* Stack pivoting detected */
      stack_pivoting_detected ( reporter_address , ( unsigned int ) stack , return_address , 0 , 0 );
    }
  }

///////////////////////

/* Si tengo alguna pareja LOGUEADA ( analizar este caso, ya que podria haber un ROP en camino ) */
  if ( ( unsigned int ) logpage & 0xfff )
  {
  /* Si el STACK POINTER actual NO coincide con el LOGUEADO */
    if ( stack != logpage -> stack_pointer )
    {
    /* Si el STACK es MAYOR al LOGUEADO ( se SALTEARON entradas ) */
      if ( logpage -> stack_pointer < stack )
      {
      /* Si el RETURN ADDRESS tambien fue modificado */
        if ( return_address != logpage -> return_address )
        {
        /* Recorro entrada por entrada */
          for ( logpage2 = logpage ; ( unsigned int ) logpage2 & 0xfff ; logpage2 ++ )
          {
          /* Si tengo el ESP actual */
            if ( stack == logpage2 -> stack_pointer )
            {
            /* Limpio las entradas SALTEADAS */
              while ( logpage != logpage2 )
              {
              /* Limpio la estructura */
                logpage -> stack_pointer = 0;
                logpage -> return_address = 0;

              /* Avanzo a al proxima entrada */
                logpage ++;
              }

            /* Me posiciono en la entrada actual */
              logpage = logpage2;

            /* Dejo de buscar */
              break;
            }
          }

        /* Si la entrada NO pudo ser encontrada */
          if ( logpage != logpage2 )
          {
          /* Stack pointer alterado */
            stack_pointer_modified ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
          }
        }
      /* Si el RETURN ADDRESS no fue MODIFICADO */
        else
        {
        /* Stack pointer alterado */
          stack_pointer_modified ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
        }
      }
    /* Si el STACK es MENOR al LOGUEADO */
      else
      {
      /* Si el RETURN ADDRESS es el correcto ( Comportamiento tipico de la funcion "alloca_probe/chkstk" ) */
        if ( return_address == logpage -> return_address )
        {
        /* Lo dejo pasar */
        }
      /* Si el RETURN ADDRESS tambien cambio */
        else
        {
        /* Stack pointer alterado */
          stack_pointer_modified ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
        }
      }
    }

  /* Si el RETURN ADDRESS actual NO coincide con el LOGUEADO */
    if ( return_address != logpage -> return_address )
    {
    /* Return address alterado */
      return_address_modified ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );

    /* Marco el FLAG para no seguir chequeando ( Podría ser una direccion de memoria NO MAPEADA ) */
      continue_check = FALSE;
    }

  /* Si el BASE POINTER actual NO coincide con el LOGUEADO */
    if ( registers -> ebp != logpage -> base_pointer )
    {
    /* Stack pointer alterado */
      base_pointer_modified ( reporter_address , registers -> ebp , return_address , logpage -> base_pointer , logpage -> return_address );
    }

  /* Limpio la ultima dupla */
    logpage -> stack_pointer = 0;
    logpage -> return_address = 0;

  /* Elimino la dupla */
    logpage ++;

  /* Actualizo el puntero en la TEB */
    TEB [ 0xffc / 4 ] = ( unsigned int ) logpage;
  }

///////////////////////

/* Si los chequeos NO fueron cancelados por el USUARIO */
  if ( continue_check == TRUE )
  {
  /* Si la instruccion anterior a la que hay que RETORNAR NO es un CALL */
    if ( is_bad_caller ( ( unsigned char * ) *stack ) == TRUE )
    {
    /* Si tengo alguna pareja LOGUEADA */
      if ( ( unsigned int ) logpage & 0xfff )
      {
      /* Invalid CALL detected */
        bad_caller_detected  ( reporter_address , ( unsigned int ) stack , return_address , logpage -> stack_pointer , logpage -> return_address );
      }
      else
      {
      /* Invalid CALL detected */
        bad_caller_detected  ( reporter_address , ( unsigned int ) stack , return_address , 0 , 0 );
      }
    }
  }
}

/***************************************************************************/

void stack_allocator ( void )
{
  unsigned int *TEB;

/* Obtengo la TEB */
  TEB = ( unsigned int ) get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Alloco STACK para el CHECKER */
//  TEB [ 0xff0 / 4 ] = VirtualAlloc ( NULL , 0x4000 , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );
  TEB [ 0xff0 / 4 ] = VirtualAlloc ( NULL , 0x10000 , MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE );

/* Desmarco el flag */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void *get_teb_address ( void )
{
  asm mov eax,fs:[0x18]

  return ( ( void * ) _EAX );  
}

/***************************************************************************/

void stack_caller_detected ( void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje */
  generate_message ( "MESSAGE: Stack execution detected" , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void stack_pivoting_detected ( void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  char msg [ 512 ];
  char line [ 256 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje a imprimir */
  sprintf ( msg , "MESSAGE: Stack pivoting detected\n" );

/* Rangos validos del stack */
  sprintf ( line , "VALID STACK RANGE: %.8x - %.8x" , TEB [ 2 ] , TEB [ 1 ] );

/* Concateno el mensaje */
  strcat ( msg , line );

/* Armo el mensaje */
  generate_message ( msg , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void stack_unusual_activity ( void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje */
  generate_message ( "MESSAGE: Inconsistent stack pointer" , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void stack_pointer_modified ( void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje */
  generate_message ( "MESSAGE: Stack pointer modified" , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void base_pointer_modified ( void *protected_function , unsigned int base_pointer , unsigned int return_address , unsigned int old_base_pointer , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje */
  generate_message ( "MESSAGE: Base pointer modified" , "BASE" , protected_function , base_pointer , return_address , old_base_pointer , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void base_pointer_unusual_activity ( void *protected_function , unsigned int base_pointer , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  char msg [ 512 ];
  char line [ 256 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje a imprimir */
  sprintf ( msg , "MESSAGE: Base pointer out of range ?\n" );

/* Rangos validos del stack */
  sprintf ( line , "VALID STACK RANGE: %.8x - %.8x\n" , TEB [ 2 ] , TEB [ 1 ] );

/* Concateno el mensaje */
  strcat ( msg , line );

/* Valor del EBP actual */
  sprintf ( line , "CURRENT EBP: %.8x" , base_pointer );

/* Concateno el mensaje */
  strcat ( msg , line );

/* Armo el mensaje */
  generate_message ( msg , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void return_address_modified ( void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje */
  generate_message ( "MESSAGE: Return address modified" , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

void bad_caller_detected ( void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address )
{
  char buffer [ 1024 ];
  unsigned int *TEB;
  int ret;

/* Obtengo la direccion de la TEB */
  TEB = get_teb_address ();

/* Marco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = TRUE;

/* Armo el mensaje */
  generate_message ( "MESSAGE: Invalid CALL instruction detected" , "STACK" , protected_function , stack , return_address , old_stack , old_return_address , buffer );

/* Mensaje de aviso al usuario */
  ret = alert_message ( "Sentinel: Abnormal activity detected" , buffer );

/* Si el usuario quiere parar el proceso */
  if ( ret == TRUE )
  {
  /* Cierro el proceso */
    ExitProcess ( 0 );
  }

/* Desmarco al FLAG para SABER que estoy llamando a APIs */
  TEB [ 0xff8 / 4 ] = FALSE;
}

/***************************************************************************/

int is_bad_caller ( unsigned char *return_address )
{
  int ret = TRUE;

/* Si el return address esta en cero ( ESTO ES UN HACK !!!!!!!! ) */
  if ( return_address == NULL )
  {
  /* Asumo que es valido */
    return ( FALSE );    
  }

/* Si es un "CALL RELATIVO" */
  if ( return_address [ -5 ] == 0xe8 )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [REG]" */
  else if ( ( return_address [ -2 ] == 0xff ) && ( ( 0x10 <= return_address [ -1 ] ) && ( return_address [ -1 ] < 0x18 ) ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL REG" */
  else if ( ( return_address [ -2 ] == 0xff ) && ( ( 0xd0 <= return_address [ -1 ] ) && ( return_address [ -1 ] < 0xd8 ) ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [REG+8b]" */
  else if ( ( return_address [ -3 ] == 0xff ) && ( ( 0x50 <= return_address [ -2 ] ) && ( return_address [ -2 ] < 0x58 ) ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [REG+REG*4+8b]" */
  else if ( ( return_address [ -4 ] == 0xff ) && ( return_address [ -3 ] == 0x54 ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [ADDRESS]" */
  else if ( ( return_address [ -6 ] == 0xff ) && ( return_address [ -5 ] == 0x15 ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [REG+32b]" */
  else if ( ( return_address [ -6 ] == 0xff ) && ( ( 0x90 <= return_address [ -5 ] ) && ( return_address [ -5 ] < 0x98 ) ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [REG+REG*n+32b]" */
  else if ( ( return_address [ -7 ] == 0xff ) && ( ( 0x90 <= return_address [ -6 ] ) && ( return_address [ -6 ] < 0x98 ) ) )
  {
  /* Return address valido */
    ret = FALSE;
  }
/* Si es un "CALL [REG*4+32b]" */
  else if ( ( return_address [ -7 ] == 0xff ) && ( return_address [ -6 ] == 0x14 ) && ( ( return_address [ -5 ] & 0x0f ) == 0x0d ) )
  {
  /* Return address valido */
    ret = FALSE;
  }

/* Si NO pude identificar el CALL */
  if ( ret == TRUE )
  {
//    asm int 3
  }

  return ( ret );
}

/***************************************************************************/

char *generate_message ( char *error , char *register_type , void *protected_function , unsigned int stack , unsigned int return_address , unsigned int old_stack , unsigned int old_return_address , char *buffer )
{
  char process_name [ 1024 ];
  char module_name [ 1024 ];
  char function_name [ 256 ];
  char line [ 256 ];
  int ret;

/* Obtengo el nombre del proceso donde estoy corriendo */
  ret = GetMyProcessName ( pid , process_name );

/* Si NO pude obtener el nombre */
  if ( ret == FALSE )
  {
  /* Para imprimir algo */
    strcpy ( process_name , "-" );
  }

/* Obtengo el nombre del modulo que reporta la actividad */
  ret = GetModuleNameByAddress ( pid , protected_function , module_name );

/* Si NO pude obtener el nombre */
  if ( ret == FALSE )
  {
  /* Para imprimir algo */
    strcpy ( module_name , "-" );
  }

/* Nombre de la funcion que REPORTA la actividad */
  GetFunctionNameByAddress ( pid , module_name , ( unsigned int ) protected_function , function_name );

/* Proceso que reporta la actividad */
  sprintf ( buffer , "PROCESS NAME: %s\n" , process_name );

/* Proceso que reporta la actividad */
  sprintf ( line , "PROCESS ID: %i\n" , pid );
  strcat ( buffer , line );

/* Modulo que reporta la actividad */
  sprintf ( line , "REPORTER MODULE: %s\n" , module_name );
  strcat ( buffer , line );

/* Simbolo de la funcion */
  sprintf ( line , "REPORTER FUNCTION: %s\n" , function_name );
  strcat ( buffer , line );

/* Direccion de la funcion */
  sprintf ( line , "REPORTER ADDRESS: %.8x\n" , protected_function );
  strcat ( buffer , line );

/* Mensaje a imprimir */
  sprintf ( line , "\n%s\n\n" , error );
  strcat ( buffer , line );

/* Stack pointer original */
//  sprintf ( line , "ORIGINAL STACK POINTER: %.8x\n" , old_stack );
  sprintf ( line , "ORIGINAL %s POINTER: %.8x\n" , register_type , old_stack );
  strcat ( buffer , line );

/* Stack pointer actual */
//  sprintf ( line , "CURRENT STACK POINTER: %.8x\n" , stack );
  sprintf ( line , "CURRENT %s POINTER: %.8x\n" , register_type , stack );
  strcat ( buffer , line );

/* Return address original */
  sprintf ( line , "ORIGINAL RETURN ADDRESS: %.8x\n" , old_return_address );
  strcat ( buffer , line );

/* Return address actual */
  sprintf ( line , "CURRENT RETURN ADDRESS: %.8x\n" , return_address );
  strcat ( buffer , line );

/* Pregunta al usuario */
  strcat ( buffer , "\nDo you want to stop the process ?" );

  return ( buffer );
}

/***************************************************************************/

int alert_message ( char *title , char *msg )
{
  unsigned int operation_size;
  unsigned int operation_id;
  unsigned int escritos;
  unsigned int leidos;
  int ret_id;
  int ret;

/* Suspendo TODOS los threads */
  SuspendAllMyThreads ( pid );

/* Imprimo una ventana con el mensaje */
//  ret_id = MessageBox ( NULL , msg , title , MB_YESNO | MB_ICONWARNING | MB_TOPMOST );

/* Envio el titulo */
  send_command ( sentinel_server , 0x80000002 , strlen ( title ) + 1 , title );

/* Envio el texto del mensaje a imprimir */
  send_command ( sentinel_server , 0x80000002 , strlen ( msg ) + 1 , msg );

/* Espero la respuesta del server */
  recv_command ( sentinel_server , &operation_id , &operation_size , &ret_id );

/* Restauro TODOS los threads */
  ActivateAllMyThreads ( pid );

/* Si la respuesta fue YES */
  if ( ret_id == IDYES )
  {
  /* Retorno OK */
    ret = TRUE;
  }
  else
  {
  /* Retorno NO */
    ret = FALSE;
  }

  return ( ret );
}

/***************************************************************************/

//int send_command ( HANDLE sentinel_server , unsigned int command_id , unsigned int size , unsigned char *buffer )
//{
//  unsigned int escritos;
//  unsigned int leidos;
//  int ret = FALSE;
//
///* Mando el ID del comando */
//  WriteFile ( sentinel_server , &command_id , sizeof ( command_id ) , &escritos , NULL );
//
///* Mando el size del comando */
//  WriteFile ( sentinel_server , &size , sizeof ( size ) , &escritos , NULL );
//
///* Mando la DATA */
//  WriteFile ( sentinel_server , buffer , size , &escritos , NULL );
//
//  return ( ret );
//}

/***************************************************************************/

int send_command ( SOCKET sentinel_server , unsigned int command_id , unsigned int size , unsigned char *buffer )
{
  unsigned int escritos;
  int ret = FALSE;

/* Mando el ID del comando */
//  WriteFile ( sentinel_server , &command_id , sizeof ( command_id ) , &escritos , NULL );
  escritos = send ( sentinel_server , ( const char * ) &command_id , sizeof ( command_id ) , 0 );

/* Mando el size del comando */
//  WriteFile ( sentinel_server , &size , sizeof ( size ) , &escritos , NULL );
  escritos = send ( sentinel_server , ( const char * ) &size , sizeof ( size ) , 0 );

/* Mando la DATA */
//  WriteFile ( sentinel_server , buffer , size , &escritos , NULL );
  escritos = send ( sentinel_server , ( const char * ) buffer , size , 0 );

  return ( ret );
}

/***************************************************************************/

//int recv_command ( HANDLE sentinel_server , unsigned int *command_id , unsigned int *size , unsigned char *buffer )
//{
//  unsigned int escritos;
//  unsigned int leidos;
//  int ret = TRUE;
//
///* Espero el ID del comando */
//  ReadFile ( sentinel_server , command_id , sizeof ( unsigned int * ) , &leidos , NULL );
//
///* Espero el size del comando */
//  ReadFile ( sentinel_server , size , sizeof ( unsigned int * ) , &leidos , NULL );
//
///* Espero el comando */
//  ReadFile ( sentinel_server , buffer , *size , &leidos , NULL );
//
//  return ( ret );
//}

/***************************************************************************/

int recv_command ( SOCKET sentinel_server , unsigned int *command_id , unsigned int *size , unsigned char *buffer )
{
  unsigned int leidos;
  int ret = TRUE;

/* Espero el ID del comando */
//  ReadFile ( sentinel_server , command_id , sizeof ( unsigned int * ) , &leidos , NULL );
  leidos = recv ( sentinel_server , ( char * ) command_id , sizeof ( unsigned int * ) , 0 );

/* Espero el size del comando */
//  ReadFile ( sentinel_server , size , sizeof ( unsigned int * ) , &leidos , NULL );
  leidos = recv ( sentinel_server , ( char * ) size , sizeof ( unsigned int * ) , 0 );

/* Espero el comando */
//  ReadFile ( sentinel_server , buffer , *size , &leidos , NULL );
  leidos = recv ( sentinel_server , ( char * ) buffer , *size , 0 );

  return ( ret );
}

/****************************************************************************/

int connect_to_gui ( char *ip , unsigned int port , SOCKET *sock )
{
  WORD wRequestedVersion;
  WSADATA wsaData;
  struct sockaddr_in saddr;
  int ret;
  int res;

/* Inicializo la lib de sockets */
  wRequestedVersion = 0x0202;
  WSAStartup ( wRequestedVersion , &wsaData );

/* Creo el socket */
  sentinel_server = socket ( AF_INET , SOCK_STREAM , 0 );

/* Tipo de socket a crear */
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr ( "127.0.0.1" );
  saddr.sin_port = htons ( ( unsigned short ) port );

/* Me conecto al server */
  res = connect ( sentinel_server , ( struct sockaddr * ) &saddr , sizeof ( struct sockaddr ) );

/* Si me pude conectar */
  if ( res == 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }
  else
  {
  /* Retorno ERROR */
    ret = FALSE;
  }

  return ( ret );
}

/****************************************************************************/

int SuspendAllMyThreads ( int mypid )
{
  int mytid;
  int tid;

/* Obtengo el thread actual */
  mytid = GetCurrentThreadId ();

/* Obtengo todos los threads del programa */
  while ( GetThreadIds ( mypid , &tid ) == TRUE )
  {
  /* Si NO es el mismo thread que se esta ejecutando */
    if ( mytid != tid )
    {
    /* Suspendo el thread */
      mySuspendThread ( tid );
    }
  }

  return ( TRUE );
}

/****************************************************************************/

int ActivateAllMyThreads ( int mypid )
{
  int mytid;
  int tid;

/* Obtengo el thread actual */
  mytid = GetCurrentThreadId ();

/* Obtengo todos los threads del programa */
  while ( GetThreadIds ( mypid , &tid ) == TRUE )
  {
  /* Si NO es el mismo thread que se esta ejecutando */
    if ( mytid != tid )
    {
    /* Suspendo el thread */
      myActivateThread ( tid );
    }
  }

  return ( TRUE );
}

/****************************************************************************/

int GetThreadIds ( int mypid , int *tid )
{
  THREADENTRY32 thread;
  static HANDLE handle = NULL;
  int ret = FALSE;

/* Inicializo la estructura */
  thread.dwSize = sizeof ( THREADENTRY32 );

/* Si estoy empezando un REQUEST */
  if ( handle == NULL )
  {
  /* Imagen del sistema */
    handle = CreateToolhelp32Snapshot ( TH32CS_SNAPTHREAD , 0 );

  /* Consulto por el primer thread */
    Thread32First ( handle , &thread );

  /* Si el thread pertenece a mi proceso */
    if ( ( unsigned int ) thread.th32OwnerProcessID == mypid )
    {
    /* Retorno el TID */
      *tid = thread.th32ThreadID;

    /* Retorno OK */
      ret = TRUE;
    }
  }

/* Si tengo que seguir listando */
  if ( ret == FALSE )
  {
  /* Mientras haya mas threads */
    while ( Thread32Next ( handle , &thread ) == TRUE )
    {
    /* Si el thread pertenece a mi proceso */
      if ( ( unsigned int ) thread.th32OwnerProcessID == mypid )
      {
      /* Retorno el TID */
        *tid = thread.th32ThreadID;

      /* Retorno OK */
        ret = TRUE;

      /* Dejo de buscar */
        break;
      }
    }
  }

/* Si NO hay mas threads para listar */
  if ( ret == FALSE )
  {
  /* Reinicio el listador */
    handle = NULL;
  }

  return ( ret );
}


/****************************************************************************/

int mySuspendThread ( int tid )
{
  HANDLE thandle;
  int ret;
  int res;

/* Abro el thread */
  thandle = OpenThread ( THREAD_SUSPEND_RESUME , FALSE , tid );

/* Si el thread pudo ser abierto */
  if ( thandle != NULL )
  {
  /* Suspendo el thread */
    res = SuspendThread ( thandle );

  /* Cierro el thread */
    CloseHandle ( thandle );

  /* Si el thread pudo ser suspendido */
    if ( res != -1 )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  /* Si el thread NO pudo ser suspendido */
    else
    {
    /* Retorno ERROR */
      ret = FALSE;
    }
  }

  return ( ret );
}

/****************************************************************************/

int myActivateThread ( int tid )
{
  HANDLE thandle;
  int ret;
  int res;

/* Abro el thread */
  thandle = OpenThread ( THREAD_SUSPEND_RESUME , FALSE , tid );

/* Si el thread pudo ser abierto */
  if ( thandle != NULL )
  {
  /* Suspendo el thread */
    res = ResumeThread ( thandle );

  /* Cierro el thread */
    CloseHandle ( thandle );

  /* Si el thread pudo ser suspendido */
    if ( res != -1 )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  /* Si el thread NO pudo ser suspendido */
    else
    {
    /* Retorno ERROR */
      ret = FALSE;
    }
  }

  return ( ret );
}

/***************************************************************************/

int GetMyProcessName ( int pid , char *process_name )
{
  PROCESSENTRY32 process;
  HANDLE handle;
  int ret = FALSE;
  int res;

/* Inicializo la estructura */
  process.dwSize = sizeof ( PROCESSENTRY32 );

/* Imagen del sistema */
  handle = CreateToolhelp32Snapshot ( TH32CS_SNAPPROCESS , 0 );

/* Listo todos los procesos del sistema */
  res = Process32First ( handle , &process );

/* Mientras pueda listar procesos */
  while ( res == TRUE )
  {
  /* Si es el proceso que hizo el llamado */
    if ( process.th32ProcessID == pid )
    {
    /* Copio el nombre del proceso */
      strcpy ( process_name , process.szExeFile );

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }

  /* Sigo listando procesos */
    res = Process32Next ( handle , &process );
  }

  return ( ret );
}

/***************************************************************************/

int GetModuleNameByAddress ( int pid , void *address , char *buffer )
{
  MODULEENTRY32 module;
  HANDLE handle;
  int ret = FALSE;
  int res;

/* Inicializo la estructura */
  module.dwSize = sizeof ( MODULEENTRY32 );

/* Imagen del sistema */
  handle = CreateToolhelp32Snapshot ( TH32CS_SNAPMODULE , pid );

/* Listo todos los procesos del sistema */
  res = Module32First ( handle , &module );

/* Mientras pueda listar procesos */
  while ( res == TRUE )
  {
  /* Si la direccion esta dentro del rango del modulo */
    if ( ( module.modBaseAddr <= address ) && ( address < ( module.modBaseAddr + module.modBaseSize ) ) )
    {
    /* Copio el nombre del modulo */
      strcpy ( buffer , module.szModule );

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }

  /* Sigo listando procesos */
    res = Module32Next ( handle , &module );
  }

  return ( ret );
}

/****************************************************************************/

int GetFunctionNameByAddress ( int pid , char *module , unsigned int address , char *function_name )
{
  struct _simbolo
  {
    IMAGEHLP_SYMBOL symbol;
    char name [ 256 ];
  } simbolo;
  HANDLE phandle;
  unsigned int module_base;
  unsigned int module_limit;
  int ret = FALSE;
  int res;

/* Obtengo info del modulo */
  GetModuleLimitsByAddress ( pid , address , &module_base , &module_limit );

/* Handle del proceso actual */
  phandle = GetCurrentProcess ();

/* Inicializo los simbolos */
  res = SymInitialize ( phandle , NULL , FALSE );

/* Cargo los simbolos para este modulo */
  res = SymLoadModule ( phandle , NULL , module , NULL , module_base , 0 );

/* Inicializo la estructura a donde recibir el simbolo */
  simbolo.symbol.SizeOfStruct = sizeof ( simbolo );
  simbolo.symbol.MaxNameLength = 255;

/* Levanto el siguiente simbolo */
  res = SymGetSymFromAddr ( phandle , address , 0 , ( IMAGEHLP_SYMBOL * ) &simbolo );

/* Si pude obtener un simbolo */
  if ( res == TRUE )
  {
  /* Si es una funcion EXPORTADA */
    if ( simbolo.symbol.Flags & SYMFLAG_EXPORT )
    {
    /* Retorno el nombre de la funcion */
       strcpy ( function_name , simbolo.symbol.Name );

    /* Retorno OK */
       ret = TRUE; 
    }
  }
/* Si NO pude obtener el simbolo */
  else
  {
  /* Retorno un guion */
    strcpy ( function_name , "-" );
  }

  return ( ret );
}

/***************************************************************************/

int GetModuleLimitsByAddress ( int pid , unsigned int address , unsigned int *module_base , unsigned int *module_limit )
{
  MODULEENTRY32 module;
  HANDLE handle;
  int ret = FALSE;
  int res;

/* Inicializo la estructura */
  module.dwSize = sizeof ( MODULEENTRY32 );

/* Imagen del sistema */
  handle = CreateToolhelp32Snapshot ( TH32CS_SNAPMODULE , pid );

/* Listo todos los procesos del sistema */
  res = Module32First ( handle , &module );

/* Mientras pueda listar procesos */
  while ( res == TRUE )
  {
  /* Si la direccion esta dentro del rango del modulo */
    if ( ( module.modBaseAddr <= address ) && ( address < ( module.modBaseAddr + module.modBaseSize ) ) )
    {
    /* Retorno los limites del modulo */
      *module_base = module.modBaseAddr;
      *module_limit = module.modBaseAddr + module.modBaseSize;

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }

  /* Sigo listando procesos */
    res = Module32Next ( handle , &module );
  }

  return ( ret );
}

/***************************************************************************/
