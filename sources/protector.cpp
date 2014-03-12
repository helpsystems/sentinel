/*************************************************************/

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

/*************************************************************/

/* protector.c */

/*************************************************************/

/* Includes */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>

#include "list.cpp"
#include "string.cpp"

/*************************************************************/

/* Structs */

typedef struct
{
  int valid_epilogue;
  int patched;
  unsigned int address;
  unsigned int size_in_bytes;
  unsigned int size_in_instructions;
  unsigned int childs;
} Basic_Block;

typedef struct
{
  unsigned int address;
  unsigned int module_base;
  unsigned int module_limit;
  int processed;
  int force_patch;
  unsigned int cantidad_basic_blocks;
  Basic_Block *prologue;
  List *epilogues;
} Function;

/*************************************************************/

/* Prototypes */

HANDLE OpenProcessWithPrivileges ( int , int , int );
void analyze_and_protect_module ( int , HANDLE , unsigned int , unsigned int , unsigned int , char ** );
void analyze_module_0 ( int , int , HANDLE , char * , List & , List & );

/* funciones para proteger al binario */
void protect_module ( HANDLE , List & , unsigned int , unsigned int );
void protect_function ( HANDLE , Function * , void ** , unsigned int , unsigned int );
void protect_prologue ( int , HANDLE , Function * , Basic_Block * , unsigned int * , unsigned int , unsigned int );
void protect_epilogue ( HANDLE , Function * , Basic_Block * , unsigned int * , unsigned int , unsigned int );
int is_patchable_function ( HANDLE , Function * , int );
int is_patchable_basic_block ( HANDLE , Basic_Block * );
int is_problematic_basic_block ( HANDLE , Basic_Block * );
void assembly_call ( HANDLE , unsigned int , unsigned int );
void assembly_jump ( HANDLE , unsigned int , unsigned int );
void assembly_conditional_jump ( HANDLE , unsigned char * , unsigned int , unsigned int , unsigned int );
void assembly_push ( HANDLE , unsigned int , unsigned int );

/* Funciones para acceder a la memoria del binario */
int read_memory ( HANDLE , void * , unsigned int , unsigned char * , unsigned int * );
int write_memory ( HANDLE , void * , unsigned int , unsigned char * , unsigned int * );

/*************************************************************/

/* Codigo que analiza al binario */

#include "analyzer.cpp"

/*************************************************************/

int main ( int argc , char *argv [] )
{
  HANDLE handle;
  unsigned int pusher_address;
  unsigned int poper_address;
  unsigned int size;
  char *instruccion;
  int pid;

/* Controlo los argumentos */
  if ( argc < 4 )
  {
    printf ( "\nuse: protector.exe pid pusher_address poper_address [module_to_protect [module_to_protect [...]]]\n" );
    return ( 0 );
  }

/* PID */
  pid = atoi ( argv [ 1 ] );

/* Direccion del PUSHER */
  sscanf ( argv [ 2 ] , "%x" , &pusher_address );

/* Direccion del POPER */
  sscanf ( argv [ 3 ] , "%x" , &poper_address );

/* Abro el proceso */
  if ( ( handle = OpenProcessWithPrivileges ( PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE  , FALSE ,  pid ) ) == NULL )
  {
    printf ( "process error !!!\n" );  
    return ( 0 );
  }

///////////////////////////

/* Hack para poder usar la DISTORM en OSs que no tienen las funcion "DecodePointer" */
  {
    void *p = GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "Beep" );
    unsigned long int escritos;

  /* Patcheo la funcion Beep con instrucciones */
    WriteProcessMemory ( ( HANDLE ) -1 , ( void * ) p , ( void * ) "\x8b\x44\x24\x04\xc2\x04\x00" , 7 , &escritos );
  }

///////////////////////////

/* Analizo y protejo el programa */
  analyze_and_protect_module ( pid , handle , pusher_address , poper_address , argc - 4 , &argv [ 4 ] );

  return ( 1 );
}

/****************************************************************************/

HANDLE OpenProcessWithPrivileges ( int access , int inherite , int pid )
{
  TOKEN_PRIVILEGES new_token_privileges;
  unsigned int token_handle;
  HANDLE ret;

/* Pido permiso como debugger */
  LookupPrivilegeValueA ( NULL , SE_DEBUG_NAME , &new_token_privileges.Privileges [ 0 ].Luid );

/* Abro el token */
  OpenProcessToken ( GetCurrentProcess () , TOKEN_ADJUST_PRIVILEGES , ( void ** ) &token_handle );

/* Nuevos valores de privilegio */
  new_token_privileges.PrivilegeCount = 1;
  new_token_privileges.Privileges [ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

/* Ajusto los privilegios */
  AdjustTokenPrivileges ( ( void * ) token_handle , FALSE , &new_token_privileges , sizeof ( new_token_privileges ) , NULL , NULL );

/* Abro el proceso */
  ret = OpenProcess ( access , inherite , pid );

  return ( ret );
}

/****************************************************************************/

void analyze_and_protect_module ( int pid , HANDLE phandle , unsigned int pusher_address , unsigned int poper_address , unsigned int cant_modules , char **modules_to_protect )
{
  List basic_block_structs;
  List funciones_criticas;
  List function_structs;
  List basic_blocks;
  List funciones;
  List module_bases;
  List module_limits;
  Function *funcion;
  unsigned int module_base;
  unsigned int module_limit;
  unsigned int function_address;
  unsigned int cont2;
  unsigned int cont;

  printf ( "[x] Sentinel working ...\n" );
  printf ( "[x] Process %i opened\n" , pid );

/////////////

/* Obtengo informacion del modulo a proteger */
  get_module_information ( pid , "kernel32.dll" , &module_base , &module_limit );

/* Agrego el modulo a las listas */
  module_bases.Add ( ( void * ) module_base );
  module_limits.Add ( ( void * ) module_limit );

/* Tomo un analisis basico de kernel32.dll */
  analyze_module_0 ( FALSE , pid , phandle , "kernel32.dll" , funciones , basic_blocks );
//  printf ( "len1 = %i\n" , funciones.Len () );

/////////////

/* Obtengo informacion del modulo a proteger */
  get_module_information ( pid , "ntdll.dll" , &module_base , &module_limit );

/* Agrego el modulo a las listas */
  module_bases.Add ( ( void * ) module_base );
  module_limits.Add ( ( void * ) module_limit );

/* Tomo un analisis basico de ntdll.dll */
  analyze_module_0 ( FALSE , pid , phandle , "ntdll.dll" , funciones , basic_blocks );
//  printf ( "len2 = %i\n" , funciones.Len () );

/////////////

/* Obtengo informacion del modulo a proteger */
  get_module_information ( pid , "kernelbase.dll" , &module_base , &module_limit );

/* Agrego el modulo a las listas */
  module_bases.Add ( ( void * ) module_base );
  module_limits.Add ( ( void * ) module_limit );

/* Tomo un analisis basico de ntdll.dll */
  analyze_module_0 ( FALSE , pid , phandle , "kernelbase.dll" , funciones , basic_blocks );
//  printf ( "len2 = %i\n" , funciones.Len () );

/////////////

/* Funciones targeteadas por los exploits */
  funciones_criticas.Append ( &funciones );

/////////////

/* Analizo TODOS los modulos indicados por el usuario */
  for ( cont = 0 ; cont < cant_modules ; cont ++ )
  {
  /* Obtengo informacion del modulo a proteger */
    get_module_information ( pid , modules_to_protect [ cont ] , &module_base , &module_limit );

  /* Agrego el modulo a las listas */
    module_bases.Add ( ( void * ) module_base );
    module_limits.Add ( ( void * ) module_limit );

  /* Analizo el modulo */
    analyze_module_0 ( TRUE , pid , phandle , modules_to_protect [ cont ] , funciones , basic_blocks );
  }

/////////////

/* Creo una estructura para cada funcion */
  for ( cont = 0 ; cont < funciones.Len () ; cont ++ )
  {
  /* Direccion de la funcion a procesar */
    function_address = ( unsigned int ) funciones.Get ( cont );

  /* Creo otra funcion */
    funcion = ( Function * ) malloc ( sizeof ( Function ) );

  /* Busco el MODULO al cual pertenece la funcion */
    for ( cont2 = 0 ; cont2 < module_bases.Len () ; cont2 ++ )
    {
    /* Levanto los siguientes limites */
      module_base = ( unsigned int ) module_bases.Get ( cont2 );
      module_limit = ( unsigned int ) module_limits.Get ( cont2 );

    /* Si la funcion pertenece a este modulo */
      if ( ( module_base <= function_address ) && ( function_address < module_limit ) )
      {
      /* Dejo de buscar */
        break;
      }
    }

  /* Inicializo la funcion */
    funcion -> address = function_address;
    funcion -> module_base = module_base;
    funcion -> module_limit = module_limit;
    funcion -> processed = FALSE;
    funcion -> prologue = NULL;
    funcion -> epilogues = new ( List );

  /* Si es una funcion CRITICA ( targeteadas por los exploits ) */
    if ( funciones_criticas.Find ( ( void * ) funcion -> address ) == TRUE )
    {
    /* Patcheo si o si la funcion */
      funcion -> force_patch = TRUE;
    }
  /* Si es una funcion COMUN */
    else
    {
    /* Solo patcheo la funcion si es PATCHABLE */
      funcion -> force_patch = FALSE;
    }

  /* Agrego la funcion a la lista de estructuras */
    function_structs.Add ( ( void * ) funcion );
  }

/* Obtengo TODOS los basic blocks de las funciones detectadas */
  printf ( "\n[x] Re-analyzing all modules ...\n" );
  get_basic_blocks ( phandle , funciones , function_structs , basic_blocks , basic_block_structs );

/* Protejo al programa */
  printf ( "[x] Protecting all modules ...\n" );
  protect_module ( phandle , function_structs , pusher_address , poper_address );

/* Mensaje al usuario */
  printf ( "[x] Sentinel activated\n" );
}

/****************************************************************************/

void analyze_module_0 ( int complete_analysis , int pid , HANDLE phandle , char *libname , List &functions , List &basic_blocks )
{
  unsigned int module_base;
  unsigned int module_limit;
  unsigned int cant_funciones;
  unsigned int cant_bbs;
  List tids;
  int ret;

/* Si es el analisis LIGHT */
  if ( complete_analysis == FALSE )
  {
  /* Mensaje al usuario */
    printf ( "\n" );
    printf ( "[x] Sub-analyzing %s ...\n" , libname );
  }
  else
  {
  /* Mensaje al usuario */
    printf ( "\n" );
    printf ( "[x] Analyzing %s ...\n" , libname );
  }

/* Obtengo la direccion del modulo a proteger */
  ret = get_module_information ( pid , libname , &module_base , &module_limit );

/* Si el modulo EXISTE */
  if ( ret == TRUE )
  {
  /* Mensaje al usuario */
    printf ( "[x] Module Range: %x - %x\n" , module_base , module_limit );

  /* Funciones y basic blocks detectados hasta el momento */
    cant_funciones = functions.Len ();
    cant_bbs = basic_blocks.Len ();

  /* Analizo el modulo */
    analyze_module ( complete_analysis , phandle , libname , module_base , module_limit , functions , basic_blocks );

  /* Resultado del analisis */
    printf ( "[x] Detected functions: %i\n" , functions.Len () - cant_funciones );
    printf ( "[x] Detected basic blocks: %i\n" , basic_blocks.Len () - cant_bbs );
  }
  else
  {
  /* Mensaje al usuario */
    printf ( "[ ] Error: module not found\n" );
  }
}

/*************************************************************/

void protect_module ( HANDLE phandle , List &function_structs , unsigned int pusher_address , unsigned int poper_address )
{
  unsigned int protected_functions = 0;
  Function *funcion;
  List black_list;
  List white_list;
  unsigned int cont;
  void *next_free_stub;
  void *stub;

/* Alloco memoria para el STUB */
  stub = ( void * ) VirtualAllocEx ( phandle , 0 , 0x40000 , MEM_COMMIT , PAGE_EXECUTE_READ );
  next_free_stub = stub;

//  printf ( "STUB en %x\n" , stub );

/****************/

/* Black list de funciones */
/* RE-revisar estas */
/* KERNEL32 */
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "Sleep" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "UnhandledExceptionFilter" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "RaiseException" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "WaitForSingleObject" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "WaitForMultipleObjects" ) );

/* NTDLL */
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwReadFile" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwWaitForSingleObject" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwWaitForDebugEvent" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwRemoveIoCompletion" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwCallbackReturn" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwReplyWaitReplyPort" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwDelayExecution" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwReplyWaitReceivePortEx" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "NtWaitForMultipleObjects" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwSignalAndWaitForSingleObject" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "RtlUnwind" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwReplyWaitReceivePort" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwRequestWakeupLatency" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwRequestWaitReplyPort" ) );

//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "KiUserExceptionDispatcher" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "ZwContinue" ) );
//  black_list.Add ( ( void * ) GetProcAddress ( GetModuleHandle ( "ntdll.dll" ) , "CsrNewThread" ) );

/****************/

/* Recorro todas las funciones del programa */
  for ( cont = 0 ; cont < function_structs.Len () ; cont ++ )
  {
  /* Levanto la siguiente funcion */
    funcion = ( Function * ) function_structs.Get ( cont );

  /* Si la funcion NO esta en la black list */
    if ( black_list.Find ( ( void * ) funcion -> address ) == FALSE )
    {
    /* Si la funcion cumple con los requisitos para ser patcheada */
//      if ( ( funcion -> force_patch == TRUE ) || ( is_patchable_function ( phandle , funcion ) == TRUE ) )
      if ( is_patchable_function ( phandle , funcion , funcion -> force_patch ) == TRUE )
      {
      /* Protejo a la funcion */
        protect_function ( phandle , funcion , &next_free_stub , pusher_address , poper_address );

      /* Incremento la cantidad de funciones PATCHEADAS */
        protected_functions ++;
      }
    }
  }

/* Imprimo la cantidad de funciones protegidas */
  printf ( "[x] Protected functions: %i/%i\n" , protected_functions , function_structs.Len () );
}

/*************************************************************/

void protect_function ( HANDLE phandle , Function *funcion , void **next_free_stub , unsigned int pusher_address , unsigned int poper_address )
{
  Basic_Block *epilogue;
  unsigned int cont;

/* Si la funcion tiene un SOLO basic block */
//  if ( funcion -> cantidad_basic_blocks == 1 )
//  {
//  /* Protejo el prologo */
////    protect_prologue ( TRUE , phandle , funcion , funcion -> prologue , ( unsigned int * ) next_free_stub , pusher_address , poper_address );
//    protect_prologue ( FALSE , phandle , funcion , funcion -> prologue , ( unsigned int * ) next_free_stub , pusher_address , poper_address );
//  }
//  else
  {
  /* Primero protejo los EPILOGOS */
  /* Recorro todos los epilogos de la funcion */
    for ( cont = 0 ; cont < funcion -> epilogues -> Len () ; cont ++ )
    {
    /* Levanto el siguiente EPILOGO */
      epilogue = ( Basic_Block * ) funcion -> epilogues -> Get ( cont );

    /* Si el EPILOGO no fue patcheado */
      if ( epilogue -> patched == FALSE )
      {
      /* Protejo todos los epilogos */
        protect_epilogue ( phandle , funcion , epilogue , ( unsigned int * ) next_free_stub , pusher_address , poper_address );

      /* Lo marco como PATCHEADO */
        epilogue -> patched = TRUE;
      }
    }

  /* Protejo el prologo */
    protect_prologue ( FALSE , phandle , funcion , funcion -> prologue , ( unsigned int * ) next_free_stub , pusher_address , poper_address );

  /* Lo marco como PATCHEADO */
    funcion -> prologue -> patched = TRUE;
  }
}

/*************************************************************/

void protect_prologue ( int reallocate , HANDLE phandle , Function *funcion , Basic_Block *prologue , unsigned int *next_free_stub , unsigned int pusher_address , unsigned int poper_address )
{
  int conditional_jump = FALSE;
  unsigned int stub_pos = 0;
  unsigned int bb_pos = 0;
  unsigned int destination;
  unsigned int escritos;
  unsigned int leidos;
  unsigned int isize;
  unsigned int cont;
  unsigned char padding = 0xcc;
  char buffer [ 16 ];
  char *instruction;

/* Recorro instruccion por instruccion */
  for ( cont = 0 ; cont < prologue -> size_in_instructions ; cont ++ )
  {
  /* Si es la primera instruccion */
    if ( cont == 0 )
    {
    /* Paso como argumento la direccion de la funcion */
      assembly_push ( phandle , *next_free_stub + stub_pos , funcion -> address );

    /* Avanzo en el STUB */
      stub_pos += 5;

    /* Pongo un CALL en el STUB al PUSHER */
//      assembly_call ( phandle , ( void * ) ( *next_free_stub + stub_pos ) , 0x90909090 );
      assembly_call ( phandle , *next_free_stub + stub_pos , pusher_address );

    /* Avanzo en el STUB */
      stub_pos += 5;

    /* Restauro el stack */
      write_memory ( phandle , ( void * ) ( *next_free_stub + stub_pos ) , 3 , "\x83\xc4\x04" , &escritos );    

    /* Avanzo en el STUB */
      stub_pos += 3;
    }

  /* Desensamblo la siguiente instruccion */
    instruction = disassembly ( phandle , prologue -> address + bb_pos , &isize );
//    printf ( "%s\n" , instruction );

  /* Si es un CALL RELATIVO */
    if ( is_relative_call ( instruction ) == TRUE )
    {
    /* Obtengo el destino del CALL */
      destination = get_destination_address ( instruction );

    /* Ensamblo un CALL desde es STUB a la funcion DESTINO */
      assembly_call ( phandle , *next_free_stub + stub_pos , destination );
    }
  /* Si es un JUMP CONDICIONAL */
    else if ( is_conditional_jump ( instruction ) == TRUE )
    {
    /* Obtengo el destino del CALL */
      destination = get_destination_address ( instruction );

    /* Leo los bytecodes de la instruccion */
      read_memory ( phandle , ( void * ) ( prologue -> address + bb_pos ) , isize , buffer , &leidos );

    /* Ensamblo un CALL desde el STUB a la funcion DESTINO */
      assembly_conditional_jump ( phandle , buffer , isize , *next_free_stub + stub_pos , destination );

    /* Avanzo en el STUB */
      stub_pos += 6;

    /* Pongo un JUMP al camino NEGATIVO ( si la condicion NO se cumple ) */
      assembly_jump ( phandle , *next_free_stub + stub_pos , prologue -> address + bb_pos + isize );

    /* Avanzo en el STUB */
      stub_pos += 5;

    /* Compenso al diferencia en el size de la instruccion condicional original */
      stub_pos -= isize;

    /* Para NO poner un JUMP que retorne al final del basic block */
      conditional_jump = TRUE;
    }
  /* Si es un JUMP INCONDICIONAL RELATIVO */
    else if ( is_relative_inconditional_jump ( instruction ) == TRUE )
    {
    /* Obtengo el destino del CALL */
      destination = get_destination_address ( instruction );

    /* Ensamblo un JUMP desde es STUB al basic block DESTINO */
      assembly_jump ( phandle , *next_free_stub + stub_pos , destination );
    }
  /* Si es una instruccion comun */
    else
    {
    /* Leo la instruccion original */
      read_memory ( phandle , ( void * ) ( prologue -> address + bb_pos ) , isize , buffer , &leidos );    

    /* Muevo la instruccion al STUB */
      write_memory ( phandle , ( void * ) ( *next_free_stub + stub_pos ) , isize , buffer , &escritos );    
    }
    
  /* Avanzo en el STUB */
    stub_pos += isize;

  /* Avanzo el en basic block */
    bb_pos += isize;

  /* Si tengo lugar para poner un CALL al PUSHER */
    if ( bb_pos >= 5 )
    {
    /* Si NO tengo que mover TODO el basic block */
      if ( reallocate == FALSE )
      {
      /* Ya me alcanza para poner un CALL */
        break;
      }
    }
  }

/* Relleno las instrucciones movidas con BREAKPOINTS */
  for ( cont = 0 ; cont < bb_pos ; cont ++ )
  {
  /* Escribo el siguiente byte */
    write_memory ( phandle , ( void * ) ( prologue -> address + cont ) , 1 , ( char * ) &padding , &escritos );
  }

/* Pongo un JUMP en el principio del basic block al STUB */
  assembly_jump ( phandle , prologue -> address , *next_free_stub );

/* Si el basic block NO termina con un JUMP CONDICIONAL */
  if ( conditional_jump == FALSE )
  {
  /* Pongo un JUMP del STUB al basic block */
    assembly_jump ( phandle , *next_free_stub + stub_pos , prologue -> address + bb_pos );

  /* Avanzo en el STUB */
    stub_pos += 5;
  }

/* Apunto a la proxima posicion LIBRE en el STUB */
  *next_free_stub += stub_pos;
}

/*************************************************************/

void protect_epilogue ( HANDLE phandle , Function *funcion , Basic_Block *epilogue , unsigned int *next_free_stub , unsigned int pusher_address , unsigned int poper_address )
{
  unsigned int byte_counter = 0;
  unsigned int stub_pos = 0;
  unsigned int bb_pos = 0;
  unsigned int offset = 0;
  unsigned int start_address;
  unsigned int destination;
  unsigned int escritos;
  unsigned int leidos;
  unsigned int isize;
  unsigned int cont;
  unsigned char padding = 0xcc;
  char buffer [ 16 ];
  char *instruction;
  List addresses;
  List sizes;

/* Recorro TODAS las instrucciones del EPILOGO */
  for ( cont = 0 ; cont < epilogue -> size_in_instructions ; cont ++ )
  {
  /* Levanto la siguiente instruccion */
    instruction = disassembly ( phandle , epilogue -> address + offset , &isize );

  /* Agrego la instruccion a las listas */
    sizes.Add ( ( void * ) isize );
    addresses.Add ( ( void * ) ( epilogue -> address + offset ) );

  /* Avanzo en el basic block */
    offset += isize;
  }

/* Recorro la lista de atras hacia adelante buscando los 5 bytes que necesito */
  for ( cont = 1 ; cont <= sizes.Len () ; cont ++ )
  {
  /* Sumo la siguiente instruccion */
    byte_counter += ( unsigned int ) sizes.Get ( sizes.Len () - cont );

  /* Si tengo los 5 bytes que necesito */
    if ( byte_counter >= 5 )
    {
    /* Me quedo con la direccion de la instruccion desde donde tengo que patchear */
      start_address = ( unsigned int ) addresses.Get ( sizes.Len () - cont ); 

    /* Dejo de buscar */
      break;
    }
  }  

/* Recorro las instrucciones del EPILOGO */
  for ( cont = 0 ; cont < epilogue -> size_in_instructions ; cont ++ )
  {
  /* Desensamblo la siguiente instruccion */
    instruction = disassembly ( phandle , epilogue -> address + bb_pos , &isize );

  /* Si no llegue a la direccion donde patchear */
    if ( epilogue -> address + bb_pos < start_address )
    {
    /* Avanzo en el basic block */
      bb_pos += isize;

    /* Paso a la siguiente */
      continue;
    }

  /* Si es la ultima instruccion del basic block */
    if ( cont + 1 == epilogue -> size_in_instructions )
    {
    /* Paso como argumento la direccion del epilogo */
      assembly_push ( phandle , *next_free_stub + stub_pos , epilogue -> address );

    /* Avanzo en el STUB */
      stub_pos += 5;

    /* Pongo un CALL al POPER */
      assembly_call ( phandle , *next_free_stub + stub_pos , poper_address );

    /* Avanzo en el STUB */
      stub_pos += 5;

    /* Restauro el stack */
      write_memory ( phandle , ( void * ) ( *next_free_stub + stub_pos ) , 3 , "\x83\xc4\x04" , &escritos );    

    /* Avanzo en el STUB */
      stub_pos += 3;
    }

  /* Si es un CALL RELATIVO */
    if ( is_relative_call ( instruction ) == TRUE )
    {
    /* Obtengo el destino del CALL */
      destination = get_destination_address ( instruction );

    /* Ensamblo un CALL desde es STUB a la funcion DESTINO */
      assembly_call ( phandle , *next_free_stub + stub_pos , destination );
    }
  /* Si es un JUMP INCONDICIONAL RELATIVO */
    else if ( is_relative_inconditional_jump ( instruction ) == TRUE )
    {
    /* Obtengo el destino del CALL */
      destination = get_destination_address ( instruction );

    /* Ensamblo un JUMP desde es STUB al basic block DESTINO */
      assembly_jump ( phandle , *next_free_stub + stub_pos , destination );
    }
  /* Si es una instruccion comun */
    else
    {
    /* Leo la instruccion original */
      read_memory ( phandle , ( void * ) ( epilogue -> address + bb_pos ) , isize , buffer , &leidos );    

    /* Muevo la instruccion al STUB */
      write_memory ( phandle , ( void * ) ( *next_free_stub + stub_pos ) , isize , buffer , &escritos );    
    }
    
  /* Avanzo en el STUB */
    stub_pos += isize;

  /* Avanzo en el basic block */
    bb_pos += isize;
  }

/* Relleno las instrucciones movidas con BREAKPOINTS */
  for ( cont = 0 ; cont < byte_counter ; cont ++ )
  {
  /* Escribo el siguiente byte */
    write_memory ( phandle , ( void * ) ( start_address + cont ) , 1 , ( char * ) &padding , &escritos );
  }

/* Pongo un JUMP en el principio del basic block al STUB */
  assembly_jump ( phandle , start_address , *next_free_stub );

/* Apunto a la proxima posicion LIBRE en el STUB */
  *next_free_stub += stub_pos;
}

/*************************************************************/

int is_patchable_function ( HANDLE phandle , Function *funcion , int force_patch )
{
  Basic_Block *basic_block;
  unsigned int epilogues_ok = 0;
  unsigned int cont;
  int ret = FALSE;

//  nicolas9

/* Si hay lugar en el PROLOGO */
  if ( funcion -> prologue -> size_in_bytes >= 5 )
  {
  /* Si la funcion tiene epilogos */
    if ( funcion -> epilogues -> Len () > 0 )
    {
    /* Recorro todos los EPILOGOS */  
      for ( cont = 0 ; cont < funcion -> epilogues -> Len () ; cont ++ )
      {
      /* Levanto el siguiente epilogo */
        basic_block = ( Basic_Block * ) funcion -> epilogues -> Get ( cont );

//        printf ( "epilogue %x\n" , basic_block -> address );

      /* Si el PROLOGO es el EPILOGO */
        if ( funcion -> prologue -> address == basic_block -> address )
        {
        /* Si NO tengo lugar para PATCHEAR ambos */
          if ( is_patchable_basic_block ( phandle , basic_block ) == FALSE )
          {
//            printf ( "no puedo con este %x !!!\n" , basic_block -> address );

          /* Paso al siguiente basic block */
            continue;
          }
        }

      /* Si es un epilogo VALIDO */
        if ( basic_block -> valid_epilogue == TRUE )
        {
        /* Si hay lugar en el EPILOGO */
          if ( basic_block -> size_in_bytes >= 5 )
          {
          /* Si el EPILOGO no hace cosas raras con el STACK */
            if ( ( force_patch == TRUE ) || ( is_problematic_basic_block ( phandle , basic_block ) == FALSE ) )
            {
            /* Este epilogo puede ser patcheado */
              epilogues_ok ++;
            }
          }
        }
      }

    /* Si TODOS los epilogos son PATCHEABLES */
      if ( funcion -> epilogues -> Len () == epilogues_ok )
      {
      /* Retorno OK */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

/*************************************************************/

int is_patchable_basic_block ( HANDLE phandle , Basic_Block *basic_block )
{
  char *instruction;
  unsigned int bb_pos = 0;
  unsigned int isize;
  unsigned int cont;
  int ret = FALSE;

/* Recorro todas las instrucciones del basic block */
  for ( cont = 0 ; cont < basic_block -> size_in_instructions ; cont ++ )
  {
  /* Levanto la siguiente instruccion */
    instruction = disassembly ( phandle , basic_block -> address + bb_pos , &isize );

  /* Avanzo en el basic block */
    bb_pos += isize;

  /* Si tengo los 5 bytes para patchear el PROLOGO */
    if ( bb_pos >= 5 )
    {
    /* Si me quedan 5 bytes para el EPILOGO */
      if ( basic_block -> size_in_bytes - bb_pos >= 5 )
      {
      /* Puedo poner los chequeos */
        ret = TRUE;
      }

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

/*************************************************************/

int is_problematic_basic_block ( HANDLE phandle , Basic_Block *basic_block )
{
  unsigned int byte_counter = 0;
  unsigned int bb_pos = 0;
  unsigned int isize;
  unsigned int cont;
  char *instruction;
  int ret = FALSE;
  List addresses;
  List sizes;

/* Recorro todas las instrucciones del basic block */
  for ( cont = 0 ; cont < basic_block -> size_in_instructions ; cont ++ )
  {
  /* Desensamblo la siguiente instruccion */
    instruction = disassembly ( phandle , basic_block -> address + bb_pos , &isize );

  /* Agrego la instruccion a las listas */
    sizes.Add ( ( void * ) isize );
    addresses.Add ( ( void * ) ( basic_block -> address + bb_pos ) );

  /* Tipico comportamiento de "SEH_prolog" y "SEH_epilog" */
    if ( strncmp ( instruction , "mov [fs:0x0]," , 13 ) == 0 )
    {
    /* No puedo confiar en este basic block */      
      return ( TRUE );
    }

  /* Si es la ANTE-ULTIMA instruccion */
    if ( cont + 1 == basic_block -> size_in_instructions - 1 )
    {
    /* Si la instruccion es un PUSH */
      if ( strncmp ( instruction , "push" , 4 ) == 0 )
      {
      /* No puedo confiar en este basic block */      
        return ( TRUE );
      }
    }

  /* Avanzo en el basic block */
    bb_pos += isize;
  }

/* Si el epilogo es PATCHEABLE */
  if ( ret == FALSE )
  {
  /* Recorro las instrucciones de atras hacia adelante */
    for ( cont = 0 ; cont < addresses.Len () ; cont ++ )
    {
    /* Levanto la siguiente instruccion */
      instruction = disassembly ( phandle , ( unsigned int ) addresses.Get ( addresses.Len () - cont - 1 ) , &isize );

    /* Sigo contando bytes */
      byte_counter += isize;

    /* Si hay algun CALL en el medio ( hasta que no pueda handlear breakpoints desde adedntro ) */
      if ( strncmp ( instruction , "call" , 4 ) == 0 )
      {
//        printf ( "NO PUEDO PATCHEAR ESTE BB: %x\n" , basic_block -> address );

      /* Por ahora NO patcheo estos basic blocks */
        ret = TRUE;    

      /* Dejo de buscar */
        break;
      }

    /* Si tengo la cantidad de bytes suficiente */
      if ( byte_counter >= 5 )
      {
      /* Dejo de buscar */
        break;
      }
    }
  }

  return ( ret );
}

/*************************************************************/

void assembly_call ( HANDLE phandle , unsigned int source , unsigned int destination )
{
  unsigned int escritos;
  int distancia;
  char buffer [ 5 ];

/* Fabrico la instruccion */
  buffer [ 0 ] = 0xe8;

/* Calculo la distancia */
  * ( int * ) &buffer [ 1 ] = ( int ) destination - ( int ) ( source + 5 );

/* Escribo la instruccion */
  write_memory ( phandle , ( void * ) source , 5 , buffer , &escritos );
}

/*************************************************************/

void assembly_jump ( HANDLE phandle , unsigned int source , unsigned int destination )
{
  unsigned int escritos;
  int distancia;
  char buffer [ 5 ];

/* Fabrico la instruccion */
  buffer [ 0 ] = 0xe9;

/* Calculo la distancia */
  * ( int * ) &buffer [ 1 ] = ( int ) destination - ( int ) ( source + 5 );

/* Escribo la instruccion */
  write_memory ( phandle , ( void * ) source , 5 , buffer , &escritos );
}

/*************************************************************/

void assembly_conditional_jump ( HANDLE phandle , unsigned char *bytecodes , unsigned int size , unsigned int source , unsigned int destination )
{
  unsigned char buffer [ 6 ];
  unsigned int escritos;
  int distancia;

/* Fabrico la instruccion */
  buffer [ 0 ] = 0x0f;

/* Si es un jump condicional CORTO */
  if ( size == 2 )
  {
  /* Obtengo el bytecode de la instruccion */
    buffer [ 1 ] = bytecodes [ 0 ] + 0x10;
  }
/* Si es un jump condicional LARGO */
  else if ( size == 6 )
  {
  /* Obtengo el bytecode de la instruccion */
    buffer [ 1 ] = bytecodes [ 1 ];
  }
/* Error */
  else
  {
    printf ( "invalid conditional jump\n" );
    exit ( 0 );
  }

/* Calculo la distancia */
  * ( int * ) &buffer [ 2 ] = ( int ) destination - ( int ) ( source + 6 );

/* Escribo la instruccion */
  write_memory ( phandle , ( void * ) source , 6 , buffer , &escritos );
}

/*************************************************************/

void assembly_push ( HANDLE phandle , unsigned int address , unsigned int value )
{
  unsigned int escritos;
  char buffer [ 5 ];
  
/* Fabrico la instruccion */
  buffer [ 0 ] = 0x68;

/* Calculo la distancia */
  * ( unsigned int * ) &buffer [ 1 ] = value;

/* Escribo la instruccion */
  write_memory ( phandle , ( void * ) address , 5 , buffer , &escritos );
}

/*************************************************************/

int read_memory ( HANDLE phandle , void *address , unsigned int size , unsigned char *buffer , unsigned int *leidos )
{
  int ret;

/* Leo memoria */
  ret = ReadProcessMemory ( phandle , address , ( void * ) buffer , size , ( DWORD * ) leidos );

  return ( ret );
}

/*************************************************************/

int write_memory ( HANDLE phandle , void *address , unsigned int size , unsigned char *buffer , unsigned int *escritos )
{
  int ret;

/* Escribo memoria */
  ret = WriteProcessMemory ( phandle , address , ( void * ) buffer , size , ( DWORD * ) escritos );

  return ( ret );
}

/*************************************************************/
