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

/* analyzer.cpp */

/*************************************************************/

/* Prototypes */

char *disassembly ( HANDLE , unsigned int , unsigned int * );
char *bin2asm ( unsigned int , unsigned char * , unsigned int * );
void GetSymbols ( HANDLE , char * , unsigned int , unsigned int , List & , List & );

int get_module_information ( int , char * , unsigned int * , unsigned int * );
void analyze_module ( int , HANDLE , char * , unsigned int , unsigned int , List & , List & );
void get_sensitive_functions ( HANDLE , char * , void * , void * , List & );
void get_functions ( HANDLE , char * , void * , void * , List & , List & );
void detect_basic_blocks ( HANDLE , unsigned int , unsigned int , List & , List & , List & );
void get_basic_blocks ( HANDLE , List & , List & , List & , List & );
void get_flowchart ( unsigned int , List * , List & );
void get_first_flowchart_analysis ( HANDLE , unsigned int , unsigned int , unsigned int , unsigned int , List & , List & );
void get_second_flowchart_analysis ( unsigned int , HANDLE , unsigned int , unsigned int , unsigned int , unsigned int , List & , List & , List & , List & );
int get_section_information ( HANDLE , void * , char * , unsigned int * , unsigned int * );

is_prologue_beginning ( HANDLE , unsigned int );
int is_conditional_jump ( char * );
int is_relative_inconditional_jump ( char * );
int is_inconditional_jump ( char * );
int is_basic_block_end ( char * );
int is_relative_call ( char * );
int is_call ( char * );
int is_jump_table ( char * );
void get_jtable_pointers ( HANDLE , char * , unsigned int , unsigned int , List & );
unsigned int get_jtable_base ( char * );
unsigned int get_destination_address ( char * );

/********************************************************/

/* Codigo usado por Distorm */

/* Static size of strings. Do not change this value. Keep Python wrapper in sync. */
#define MAX_TEXT_SIZE (48)
typedef struct
{
  unsigned int length;
  unsigned char p [MAX_TEXT_SIZE]; /* p is a null terminated string. */
} _WString;

/*
 * Old decoded instruction structure in text format.
 * Used only for backward compatibility with diStorm64.
 * This structure holds all information the disassembler generates per instruction.
 */

typedef struct
{
  _WString mnemonic; /* Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc. */
  _WString operands; /* Operands of the decoded instruction, up to 3 operands, comma-seperated. */
  _WString instructionHex; /* Hex dump - little endian, including prefixes. */
  unsigned int size; /* Size of decoded instruction. */
//  _OffsetType offset; /* Start offset of the decoded instruction. */
  unsigned int offset; /* Start offset of the decoded instruction. */
} _DecodedInst;

/* Decodes modes of the disassembler, 16 bits or 32 bits or 64 bits for AMD64, x86-64. */
typedef enum { Decode16Bits = 0, Decode32Bits = 1, Decode64Bits = 2 } _DecodeType;

/* Return code of the decoding function. */
typedef enum { DECRES_NONE, DECRES_SUCCESS, DECRES_MEMORYERR, DECRES_INPUTERR, DECRES_FILTERED } _DecodeResult;

#define SYMFLAG_EXPORT 0x200

/****************************************************************************/

char *disassembly ( HANDLE phandle , unsigned int address , unsigned int *isize )
{
  unsigned int leidos;
  char bytecodes [ 16 ];
  char *instruction;

/* Levanto la siguiente posible instruccion */
  read_memory ( phandle , ( void * ) address , sizeof ( bytecodes ) , bytecodes , &leidos );

/* Desensamblo la siguiente instruccion */
  instruction = bin2asm ( address , bytecodes , isize );

  return ( instruction );
}

/****************************************************************************/

char *bin2asm ( unsigned int address , unsigned char *bytecode , unsigned int *bytes_interpretados )
{
  static int ( *distorm_decode32 ) ( unsigned int , unsigned char * , unsigned int , unsigned int , void * , unsigned int , unsigned int * ) = NULL;
  static char instruction [ 256 ];
  static HMODULE lib;
  char *p;
  _DecodedInst decodedInstructions [ 256 ];
  unsigned int counter;
  int ret;

/* Si es la primera vez */
  if ( distorm_decode32 == NULL )
  {
  /* Resuelvo la direccion de la lib */
    lib = LoadLibrary ( "distorm3.dll" );
//    printf ( "lib = %x\n" , lib );

  /* Resuelvo la direccion de la funcion */
    ( void * ) distorm_decode32 = ( void * ) GetProcAddress ( lib , "distorm_decode32" );
//    printf ( "%x\n" , distorm_decode32 );
  }

/* Desensamblo la instruccion */
  ret = distorm_decode32 ( address , bytecode ,  16 , Decode32Bits , &decodedInstructions , 16 , &counter );
//  printf ( "ret = %i\n" , ret );
//  printf ( "counter = %i\n" , counter );
//  printf ( "size = %i\n" , decodedInstructions[0].size );
//  printf ( "%s %s\n" , decodedInstructions[0].mnemonic.p , decodedInstructions[0].operands.p );

/* Si pude traducir la instruccion */
  if ( decodedInstructions[0].size > 0 )
  {
  /* Si la instruccion NO tiene operandos */
    if ( decodedInstructions[0].operands.p [0] == '\x00' )
    {
    /* Armo la instruccion a retornar */
      strcpy ( instruction , decodedInstructions[0].mnemonic.p );
    }
  /* Si la instruccion tiene operandos */
    else
    {
    /* Armo la instruccion a retornar */
      sprintf ( instruction , "%s %s" , decodedInstructions[0].mnemonic.p , decodedInstructions[0].operands.p );

    /* Busco si la instruccion tiene un ", " */
      p = strstr ( instruction , ", " );

    /* Si encontre ese ESPACIO DEMAS */
      if ( p != NULL )
      {
      /* Suprimo el espacio */
        strcpy ( p + 1 , p + 2 );
      }
    }

  /* Apunto a la instruccion */
    p = instruction;

  /* Convierto el string a MINUSCULAS */
    while ( *p != 0 )
    {
    /* Convierto el caracter a minuscula */
      *p = tolower ( *p );

    /* Avanzo en el string */
      p ++;
    }
  }
  else
  {
  /* No pude traducir la instruccion */
    strcpy ( instruction , "???" );
  }

/* Bytes usados por la instruccion */
  *bytes_interpretados = decodedInstructions[0].size;

  return ( instruction );
}

/****************************************************************************/

void GetSymbols ( HANDLE phandle , char *libname , unsigned int module_base , unsigned int module_limit , List &addresses , List &names )
{
  struct _simbolo
  {
    IMAGEHLP_SYMBOL symbol;
    char name [ 1024 ];
  } simbolo;
  String *name;
  char last_symbol [ 1024 ];
  unsigned int address;
  int ret;

/* Inicializo los simbolos */
  ret = SymInitialize ( phandle , NULL , FALSE );

/* Cargo los simbolos para este modulo */
  ret = SymLoadModule ( phandle , NULL , libname , NULL , module_base , 0 );

/* Inicializo el ultimo simbolo agregado */
  strcpy ( last_symbol , "" );

//  ret = SymEnumSymbols ( phandle , base , "" , next_symbol , NULL );
//  printf ( "ret = %x\n" , ret );

/* Recorro direccion por direccion */
  for ( address = module_base ; address < module_limit ; address ++ )
  {
    simbolo.symbol.SizeOfStruct = sizeof ( simbolo );
    simbolo.symbol.MaxNameLength = 255;

  /* Levanto el siguiente simbolo */
    ret = SymGetSymFromAddr ( phandle , address , 0 , ( IMAGEHLP_SYMBOL * ) &simbolo );

  /* Si pude obtener un simbolo */
    if ( ret == TRUE )
    {
    /* Si es una funcion EXPORTADA */
      if ( simbolo.symbol.Flags & SYMFLAG_EXPORT )
      {
      /* Si este simbolo NO lo tengo */
        if ( strcmp ( last_symbol , simbolo.symbol.Name ) != 0 )
        {
//          if ( strcmp ( simbolo.symbol.Name , "WinExec" ) == 0 )
//          {
//            printf ( "%x: %s\n" , address , simbolo.symbol.Name );
//          }

        /* Me quedo con el nombre del simbolo actual */ 
          strcpy ( last_symbol , simbolo.symbol.Name );

        /* Creo un string para el nombre del simbolo */
          name = new ( String );

        /* Seteo el simbolo */
          name -> Set ( simbolo.symbol.Name );

        /* Agrego el simbolo a las listas */
          addresses.Add ( ( void * ) address );
          names.Add ( ( void * ) name );
        }
      }
    }
  }
}

/****************************************************************************/

int get_module_information ( int pid , char *libname , unsigned int *module_base , unsigned int *module_limit )
{
  MODULEENTRY32 module;
  HANDLE phandle;
  HANDLE handle;
  int ret = FALSE;
  int res;

/* Abro el proceso */
  phandle = OpenProcessWithPrivileges ( PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE , FALSE ,  pid );

/* Si no pude abrir el proceso */
  if ( phandle == NULL )
  {
    printf ( "process error !!!\n" );
    return ( FALSE );
  }

/* Inicializo la estructura */
  module.dwSize = sizeof ( MODULEENTRY32 );

/* Imagen del sistema */
  handle = CreateToolhelp32Snapshot ( TH32CS_SNAPMODULE , pid );

/* Listo todos los procesos del sistema */
  res = Module32First ( handle , &module );

/* Mientras pueda listar procesos */
  while ( res == TRUE )
  {
  /* Si es el modulo que estoy buscando */
    if ( stricmp ( libname , module.szModule ) == 0 )
    {
    /* Retorno la base del modulo */
      *module_base = ( unsigned int ) module.modBaseAddr;
      *module_limit = ( unsigned int ) module.modBaseAddr + ( unsigned int ) module.modBaseSize;

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }

  /* Sigo listando procesos */
    res = Module32Next ( handle , &module );
  }

/* Cierro el proceso */
  CloseHandle ( phandle );

  return ( ret );
}

/****************************************************************************/

void analyze_module ( int complete_analysis , HANDLE phandle , char *module_name , unsigned int module_base , unsigned int module_limit , List &funciones , List &basic_blocks )
{
  List funciones_tentativas;
  List memory_map;
  Basic_Block *basic_block;
  Function *funcion;
  unsigned int function_address;
  unsigned int section_base;
  unsigned int section_size;
  unsigned int cont;

/* Obtengo los limites de la seccion */
  get_section_information ( phandle , ( void * ) module_base , ".text" , &section_base , &section_size );

/* Inicializo la lista donde marco todos los bytes como NO PROCESADOS */
  memory_map.Len ( section_size );

/* Lista para saber que ADDRESSES fueron procesadas */
  for ( cont = 0 ; cont < section_size ; cont ++ )
  {
  /* Agrego la siguiente ADDRESS */
    memory_map.Set ( cont , ( void * ) FALSE );
  }

/* Si solo voy a patchear las funciones SENSIBLES */
  if ( complete_analysis == FALSE )
  {
  /* Obtengo SOLO las funciones necesarias */
    get_sensitive_functions ( phandle , module_name , ( void * ) module_base , ( void * ) module_limit , funciones );
  }
  else
  {
  /* Detecto las funciones del modulo */
    get_functions ( phandle , module_name , ( void * ) module_base , ( void * ) module_limit , funciones , funciones_tentativas );
//  printf ( "funciones detectadas = %i\n" , funciones_list -> Len () );

  /* Con las funciones que tengo, detecto los basic blocks */
    detect_basic_blocks ( phandle , module_base , module_limit , funciones , basic_blocks , memory_map );

  /* Trato de matchear los "CALLs to" con el inicio de las funciones */
    for ( cont = 0 ; cont < funciones_tentativas.Len () ; cont ++ )
    {
    /* Levanto la siguiente funcion */
      function_address = ( unsigned int ) funciones_tentativas.Get ( cont );

    /* Si la direccion FUE PROCESADA */
      if ( ( int ) memory_map.Get ( function_address - module_base ) == TRUE )
      {
      /* Si es el principio de un basic block */
        if ( basic_blocks.Find ( ( void * ) function_address ) == TRUE )
        {
        /* Agrego la funcion */
          funciones.Add ( ( void * ) function_address );
        }
      }
    /* Si la direccion NO fue procesada */
      else
      {
      /* Si la funcion tiene un PROLOGO VALIDO */
        if ( is_prologue_beginning ( phandle , function_address ) == TRUE )
        {
        /* Agrego la funcion */
          funciones.Add ( ( void * ) function_address );
        }
      }
    }
  }

/* Ordeno las funciones detectadas hasta el momento */
  funciones.Sort ();

/* Ordeno los basic blocks detectados hasta el momento */
  basic_blocks.Sort ();

/* Detecto TODOS los basic blocks del programa */
  detect_basic_blocks ( phandle , module_base , module_limit , funciones , basic_blocks , memory_map );
}

/*************************************************************/

void get_sensitive_functions ( HANDLE phandle , char *module_name , void *module_base , void *module_limit , List &funciones )
{
  unsigned int size_list;
  unsigned int cont;
  void *function_address;
  char *function_name;
  char **lib_list;

  char *kernel32_list [] = {
                             "CreateFileMappingA",
                             "CreateFileMappingW",
                             "CreateProcessA",
                             "CreateProcessW",
                             "LoadLibraryA",
                             "LoadLibraryW",
                             "LoadLibraryExA",
                             "LoadLibraryExW",
                             "MapViewOfFile",
                             "MapViewOfFileEx",
                             "VirtualAlloc",
                             "VirtualAllocEx",
                             "VirtualProtect",
                             "VirtualProtectEx",
                             "WinExec",
                           };

  char *ntdll_list [] =    {
                             "ZwCreateSection",
                             "ZwCreateProcess",
                             "ZwCreateProcessEx",
                             "ZwMapViewOfSection",
                             "ZwProtectVirtualMemory",
                             "ZwSetInformationProcess",
                           };

  char *kernelbase_list [] = {
                               "CreateFileMappingW",
                               "MapViewOfFile",
                               "MapViewOfFileEx",
                               "VirtualAlloc",
                               "VirtualAllocEx",
                               "VirtualProtect",
                               "VirtualProtectEx",
                             };

/* Si el modulo es "kernel32.dll" */
  if ( strcmp ( module_name , "kernel32.dll" ) == 0 )
  {
  /* Lista de funciones a resolver */
    lib_list = kernel32_list;

  /* Cantidad de funciones a resolver */
    size_list = sizeof ( kernel32_list ) / sizeof ( char * );
  }
/* Si el modulo es "ntdll.dll" */
  else if ( strcmp ( module_name , "ntdll.dll" ) == 0 )
  {
  /* Lista de funciones a resolver */
    lib_list = ntdll_list;

  /* Cantidad de funciones a resolver */
    size_list = sizeof ( ntdll_list ) / sizeof ( char * );
  }
/* Si el modulo es "kernelbase.dll" */
  else if ( strcmp ( module_name , "kernelbase.dll" ) == 0 )
  {
  /* Lista de funciones a resolver */
    lib_list = kernelbase_list;

  /* Cantidad de funciones a resolver */
    size_list = sizeof ( kernelbase_list ) / sizeof ( char * );
  }

/* Recorro todas las funciones SENSIBLES del modulo */
  for ( cont = 0 ; cont < size_list ; cont ++ )
  {
  /* Levanto la siguiente funcion */
    function_name = lib_list [ cont ];

  /* Obtengo la direccion de la funcion */
    function_address = GetProcAddress ( GetModuleHandle ( module_name ) , function_name );

  /* Si pude resolver el simbolo */
    if ( function_address != NULL )
    {
    /* Agrego la direccion de la funcion */
      funciones.Add ( function_address );
    }
  }
}

/*************************************************************/

void get_functions ( HANDLE phandle , char *module_name , void *module_base , void *module_limit , List &funciones , List &tentative_functions )
{
  List funciones_tentativas_tmp;
  List funciones_tmp;
  List addresses;
  List names;
  Function *funcion;
  unsigned int function_address;
  unsigned int destination;
  unsigned int code_base;
  unsigned int code_size;
  unsigned int leidos;
  unsigned int pcode;
  unsigned int isize;
  unsigned int cont;
  char buffer [ 16 ];
  char *instruction;
  char *part;

//  printf ( "FUNCIONES HARDCODEADAS !!!\n" );
//  funciones.Add ( ( void * ) 0x01011913 );
//  funciones.Sort ();
//  return;

///////////////

/* Obtengo la base de la seccion ".text" */
  get_section_information ( phandle , module_base , ".text" , &code_base , &code_size );
//  printf ( "%x - %x\n" , code_base , code_size );

///////////////

/* Obtengo los simbolos exportados */
  GetSymbols ( phandle , module_name , ( unsigned int ) module_base , ( unsigned int ) module_base + code_size , addresses , names );
  printf ( "[x] Detected symbols = %i\n" , addresses.Len () );

/* Recorro todas las funciones detectadas */
  for ( cont = 0 ; cont < addresses.Len () ; cont ++ )
  {
  /* Levanto la siguiente funcion */
    function_address = ( unsigned int ) addresses.Get ( cont );

  /* Si la funcion NO esta en la lista de funciones detectadas anteriormente */
    if ( funciones.Find ( ( void * ) function_address ) == FALSE )
    {
    /* Agrego la funcion a la lista de pendientes */
      funciones_tmp.Add ( ( void * ) function_address );
    }
  }

/* Agrego los simbolos NO repetidos a la lista */
  funciones.Append ( &funciones_tmp );

/* Ordeno la lista de funciones */
  funciones.Sort ();

///////////////

/* Reconozco funciones por PROLOGOS */

/* Lista para guardar las funciones DETECTADAS */
  funciones_tmp.Clear ();

/* Desensamblo desde el pricipio */
  pcode = code_base;

/* Desensamblo instruccion a instruccion */
  while ( pcode < ( code_base + code_size ) )
  {
  /* Levanto la siguiente posible instruccion */
    instruction = disassembly ( phandle , pcode , &isize );
//    printf ( "%x: %.2i %s\n" , pcode , isize , instruction );

  /* Si NO pude desensamblar la instruccion */
    if ( isize == 0 )
    {
    /* Paso al siguiente byte */
      isize = 1;

    /* Sigo con la proxima instruccion */
      continue;
    }

  /* Si es un TIPICO PROLOGO */
    if ( is_prologue_beginning ( phandle , pcode ) == TRUE )
    {
    /* Si la funcion NO fue DETECTADA */
      if ( funciones.Find ( ( void * ) pcode ) == FALSE )
      {
      /* Agrego la funcion a la lista */
        funciones_tmp.Add ( ( void * ) pcode );
      }

    /* Avanzo a la proxima instruccion */
      pcode += isize;

    /* Salteo la proxima instruccion para EVITAR FALSOS POSITIVOS */
      instruction = disassembly ( phandle , pcode , &isize );
    }

  /* Avanzo en el codigo */
    pcode += isize;
  }

/* Agrego las funciones DETECTADAS */
  funciones.Append ( &funciones_tmp );

/* Ordeno la lista de funciones detectadas por PROLOGOS */
  funciones.Sort ();

///////////////

/* Reconozco funciones por CALLs */

/* Desensamblo desde el pricipio */
  pcode = code_base;

/* Desensamblo instruccion a instruccion */
  while ( pcode < ( code_base + code_size ) )
  {
  /* Levanto la siguiente posible instruccion */
    instruction = disassembly ( phandle , pcode , &isize );
//    printf ( "%x: %.2i %s\n" , pcode , isize , instruction );

  /* Si NO pude desensamblar la instruccion */
    if ( isize == 0 )
    {
    /* Paso al siguiente byte */
      isize = 1;

    /* Sigo con la proxima instruccion */
      continue;
    }

  /* Si la funcion NO fue DETECTADA */
    if ( funciones.Find ( ( void * ) pcode ) == FALSE )
    {
    /* Si es un CALL */
      if ( is_relative_call ( instruction ) == TRUE )
      {
      /* Obtengo la direccion de la funcion */
        destination = get_destination_address ( instruction );

      /* Si la funcion esta dentro del RANGO del MODULO */
        if ( ( code_base <= destination ) && ( destination < code_base + code_size ) )
        {
        /* Si la funcion NO fue agregada */
          if ( funciones_tentativas_tmp.Find ( ( void * ) destination ) == FALSE )
          {
          /* Desensamblo la PRIMERA instruccion de la funcion */
            instruction = disassembly ( phandle , destination , &isize );

          /* Si la instruccion empieza con un TIPICO PROLOGO */
            if ( strcmp ( instruction , "push ebp" ) == 0 )
            {
            /* Si la funcion NO fue agregada */
              if ( funciones.Find ( ( void * ) destination ) == FALSE )
              {
              /* Agrego la funcion como VALIDA */
                funciones.Add ( ( void * ) destination );
              }
            }
            else
            {
            /* Agrego la funcion a la lista */
              funciones_tentativas_tmp.Add ( ( void * ) destination );
            }
          }
        }
      }
    }

  /* Avanzo en el codigo */
    pcode += isize;
  }

/* Ordeno la lista de funciones detectadas por PROLOGOS */
  funciones.Sort ();

/* Ordeno la lista de funciones detectadas por CALLs */
  funciones_tentativas_tmp.Sort ();

//////////

/* Recorro todas las funciones detectadas por CALLs */
  for ( cont = 0 ; cont < funciones_tentativas_tmp.Len () ; cont ++ )
  {
  /* Levanto la siguiente funcion */
    function_address = ( unsigned int ) funciones_tentativas_tmp.Get ( cont );

  /* Si la funcion NO fue DETECTADA por PROLOGO */
    if ( funciones.Find ( ( void * ) function_address ) == FALSE )
    {
    /* Si la funcion NO fue detectada por CALLs TO */
      if ( tentative_functions.Find ( ( void * ) function_address ) == FALSE )
      {
      /* Agrego la funcion */
        tentative_functions.Add ( ( void * ) function_address );
      }
    }
  }

//////////

/* Ordeno la lista de funciones detectadas por CALLs TO */
  tentative_functions.Sort ();
}

/*************************************************************/

void detect_basic_blocks ( HANDLE phandle , unsigned int module_base , unsigned int module_limit , List &funciones , List &basic_blocks , List &memory_map )
{
  unsigned int funcion;
  unsigned int cont;

/* Primer analisis del programa */
/* Recorro funcion por funcion */
  for ( cont = 0 ; cont < funciones.Len () ; cont ++ )
  {
  /* Levanto la siguiente direccion de funcion */
    funcion = ( unsigned int ) funciones.Get ( cont );

  /* Obtengo los basic blocks de la funcion */
    get_first_flowchart_analysis ( phandle , module_base , module_limit , funcion , funcion , basic_blocks , memory_map );
  }
}

/*************************************************************/

void get_basic_blocks ( HANDLE phandle , List &funciones , List &function_structs , List &basic_blocks , List &basic_block_structs )
{
  Basic_Block *basic_block;
  Function *funcion;
  List flowchart;
  unsigned int cont2;
  unsigned int cont;
  unsigned int pos;

/* Alloco una estructura para cada basic block */
  for ( cont = 0 ; cont < basic_blocks.Len () ; cont ++ )
  {
  /* Siguiente basic block */
    basic_block = ( Basic_Block * ) malloc ( sizeof ( Basic_Block ) );

  /* Inicializo el basic block */
    basic_block -> patched = FALSE;
    basic_block -> valid_epilogue = FALSE;
    basic_block -> address = ( unsigned int ) basic_blocks.Get ( cont );
    basic_block -> size_in_bytes = 0;
    basic_block -> size_in_instructions = 0;
    basic_block -> childs = 0;

  /* Agrego el basic block a la lista */
    basic_block_structs.Add ( ( void * ) basic_block );
  }

/* Segundo analisis del programa */
/* Recorro funcion por funcion */
  for ( cont = 0 ; cont < funciones.Len () ; cont ++ )
  {
  /* Obtengo la funcion a analizar */
    funcion = ( Function * ) function_structs.Get ( cont );

//    printf ( "lens: %i - %i\n" , function_structs.Len () , funciones.Len () );
//    printf ( "%x - %x\n" , funcion -> address , funciones.Get ( cont ) );

    if ( funcion -> address != ( unsigned int ) funciones.Get ( cont ) )
    {
      printf ( "???????\n" );
      exit ( 0 );
    }

  /* Si la funcion ya fue procesada */
    if ( funcion -> processed == TRUE )
    {
    /* Paso a la siguiente */
      continue;
    }
  /* Si todavia NO fue procesada */
    else
    {
    /* La marco como procesada */
      funcion -> processed = TRUE;
    }

  /* Obtengo los basic blocks de la funcion */
    get_second_flowchart_analysis ( 0 , phandle , funcion -> module_base , funcion -> module_limit , funcion -> address , funcion -> address , funciones , basic_blocks , basic_block_structs , flowchart );

  /* Asocio la funcion con su PROLOGO */
    funcion -> prologue = ( Basic_Block * ) flowchart.Get ( 0 );

  /* Seteo la cantidad de basic blocks que tiene la funcion */
    funcion -> cantidad_basic_blocks = flowchart.Len ();

  /* Recorro todo el flowchart buscando los EPILOGOS */
    for ( cont2 = 0 ; cont2 < flowchart.Len () ; cont2 ++ )
    {
    /* Levanto el siguiente basic block */
      basic_block = ( Basic_Block * ) flowchart.Get ( cont2 );

    /* Si el basic block es un EPILOGO */
      if ( basic_block -> childs == 0 )
      {
      /* Asocio la funcion con uno de sus epilogos */
        funcion -> epilogues -> Add ( ( void * ) basic_block );
      }
    }
  }
}

/*************************************************************/

void get_first_flowchart_analysis ( HANDLE phandle , unsigned int module_base , unsigned int module_limit , unsigned int funcion , unsigned int basic_block , List &basic_blocks , List &memory_map )
{
  List jtable_pointers;
  unsigned int next_instruction;
  unsigned int destination;
  unsigned int jtable_base;
  unsigned int isize;
  unsigned int size;
  unsigned int cont;
  int basic_block_end = FALSE;
  char *instruction;

/* Si estoy fuera de los limites del modulo */
  if ( ! ( ( module_base <= basic_block ) && ( basic_block < module_limit ) ) )
  {
  /* Dejo de avanzar */
    return;
  }

/* Si el basic block NO esta en la lista */
  if ( basic_blocks.Find ( ( void * ) basic_block ) == FALSE )
  {
  /* Tengo otro basic block */
    basic_blocks.Add ( ( void * ) basic_block );
  }  
/* Si el basic block esta en la lista */
  else
  {
  /* Quiere decir que estoy procesando un basic block repetido */
    return;
  }

/* Desde donde empiezo a desensamblar */
  next_instruction = basic_block;

/* Mientras el basic block NO termine */
  while ( basic_block_end == FALSE )
  {
  /* Desensamblo la siguiente instruccion */
    instruction = disassembly ( phandle , next_instruction , &isize );
//    printf ( "* %s\n" , instruction );

  /* Si NO pude desensamblar la instruccion */
    if ( isize > 0 )
    {
    /* Uso el SIZE de la instruccion */
      size = isize;
    }
  /* Si la instruccion pudo ser desensamblada */
    else
    {
    /* Uso 1 byte */
      size = 1;
    }

  /* Marco los bytes que ocupa la instruccion */
    for ( cont = 0 ; cont < size ; cont ++ )
    {
    /* Marco la siguiente direccion */
      memory_map.Set ( ( ( ( unsigned int ) next_instruction + cont ) - module_base ) , ( void * ) TRUE );
    }

  /* Si estoy fuera de los limites del modulo */
    if ( ! ( ( module_base <= next_instruction ) && ( next_instruction < module_limit ) ) )
    {
    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es un JUMP CONDICIONAL */
    else if ( is_conditional_jump ( instruction ) == TRUE )
    {
    /* Obtengo la direccion del basic block destino */
      destination = get_destination_address ( instruction );

    /* Avanzo por el camino del JUMP */
      get_first_flowchart_analysis ( phandle , module_base , module_limit , funcion , destination , basic_blocks , memory_map );

    /* Avanzo al siguiente basic block */
      get_first_flowchart_analysis ( phandle , module_base , module_limit , funcion , next_instruction + isize , basic_blocks , memory_map );

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es un JUMP INCONDICIONAL */
    else if ( is_inconditional_jump ( instruction ) == TRUE )
    {
    /* Si es un JUMP RELATIVO */
      if ( is_relative_inconditional_jump ( instruction ) == TRUE )
      {
      /* Obtengo la direccion del basic block destino */
        destination = get_destination_address ( instruction );

//        printf ( "%x --> dest: %x\n" , next_instruction , destination );

      /* Avanzo por el camino del JUMP */
        get_first_flowchart_analysis ( phandle , module_base , module_limit , funcion , destination , basic_blocks , memory_map );
      }
      /* Si es una JUMP TABLE */
      else if ( is_jump_table ( instruction ) == TRUE )
      {      
      /* Obtengo los punteros de la JTABLE */
        get_jtable_pointers ( phandle , instruction , module_base , module_limit , jtable_pointers );

      /* Avanzo por cada uno de los basic blocks hijos */
        for ( cont = 0 ; cont < jtable_pointers.Len () ; cont ++ )
        {
        /* Avanzo al siguiente basic block */
          get_first_flowchart_analysis ( phandle , module_base , module_limit , funcion , ( unsigned int ) jtable_pointers.Get ( cont ) , basic_blocks , memory_map );
        }
      }

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es el fin del basic block */
    else if ( is_basic_block_end ( instruction ) == TRUE )
    {
    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es un breakpoint */
    else if ( strcmp ( instruction , "int 3" ) == 0  )
    {
    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si la instruccion NO pudo ser desensamblada */
    else if ( isize == 0 )
    {
    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }

  /* Avanzo a la siguiente instruccion */
    next_instruction += isize;
  }
}

/*************************************************************/

void get_second_flowchart_analysis ( unsigned int level , HANDLE phandle , unsigned int module_base , unsigned int module_limit , unsigned int funcion , unsigned int basic_block , List &funciones , List &basic_blocks , List &basic_block_structs , List &flowchart )
{
  List jtable_pointers;
  Basic_Block *basic_block_struct;
  int basic_block_end = FALSE;
  unsigned int instruction_counter = 0;
  unsigned int next_instruction;
  unsigned int destination;
  unsigned int isize;
  unsigned int cont;
  unsigned int pos;
  char *instruction;
  int ret;

////////////////////

/* Si estoy empezando a procesar la funcion */
  if ( level == 0 )
  {
  /* Inicializo la lista donde voy a guardar los basic blocks de la funcion */
    flowchart.Clear ();
  }

/* Si estoy fuera de los limites del modulo */
  if ( ! ( ( module_base <= basic_block ) && ( basic_block < module_limit ) ) )
  {
  /* Dejo de avanzar */
    return;
  }

////////////////////

/* Busco la posicion del basic block */
  ret = basic_blocks.GetPos ( ( void * ) basic_block , &pos );

/* Si el basic block esta en la lista */
  if ( ret == TRUE )
  {
  /* Obtengo el basic block */
    basic_block_struct = ( Basic_Block * ) basic_block_structs.Get ( pos );
  }
  else
  {
    printf ( "wtf --> %x\n" , basic_block );
    exit ( 0 );
  }

/* Si el basic block NO fue procesado */
  if ( flowchart.Find ( ( void * ) basic_block_struct ) == FALSE )
  {
  /* Agrego el basic block para NO volver a procesarlo */
    flowchart.Add ( ( void * ) basic_block_struct );
  }  
/* Si el basic block fue procesado */
  else
  {
  /* Quiere decir que estoy procesando un basic block repetido */
    return;
  }

////////////////////

/* Desde donde empiezo a desensamblar */
  next_instruction = basic_block;

/* Mientras el basic block NO termine */
  while ( basic_block_end == FALSE )
  {
  /* Desensamblo la siguiente instruccion */
    instruction = disassembly ( phandle , next_instruction , &isize );

  /* Contador de instrucciones del basic block */
    instruction_counter ++;

  /* Si estoy fuera de los limites del modulo */
    if ( ! ( ( module_base <= next_instruction ) && ( next_instruction < module_limit ) ) )
    {
    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter - 1;
      basic_block_struct -> childs = 0;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si la instruccion NO pudo ser desensamblada */
    else if ( ( isize == 1 ) && ( strncmp ( instruction , "db 0x" , 5 ) == 0 ) )
    {
    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter - 1;
      basic_block_struct -> childs = 0;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es el principio de otra funcion */
//    else if ( ( basic_block != next_instruction ) && ( funciones.Find ( ( void * ) next_instruction ) == TRUE ) )
    else if ( ( funcion != next_instruction ) && ( funciones.Find ( ( void * ) next_instruction ) == TRUE ) )
    {
    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter - 1;
      basic_block_struct -> childs = 0;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es el principio de OTRO basic block */
    else if ( ( basic_block != next_instruction ) && ( basic_blocks.Find ( ( void * ) next_instruction ) == TRUE ) )
    {
    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter - 1;
      basic_block_struct -> childs = 1;

//    /* Si NO es el inicio de OTRA FUNCION */
//      if ( funciones.Find ( ( void * ) next_instruction ) == FALSE )
//      {
//        basic_block_struct -> childs = 1;
//      }

    /* Avanzo por el otro basic block */
      get_second_flowchart_analysis ( level + 1 , phandle , module_base , module_limit , funcion , next_instruction , funciones , basic_blocks , basic_block_structs , flowchart );

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es el fin del basic block */
    else if ( is_basic_block_end ( instruction ) == TRUE )
    {
    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction + isize - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter;
      basic_block_struct -> childs = 0;

    /* Marco al EPILOGO como valido */
      basic_block_struct -> valid_epilogue = TRUE;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es un JUMP CONDICIONAL */
    else if ( is_conditional_jump ( instruction ) == TRUE )
    {
    /* Obtengo la direccion del basic block destino */
      destination = get_destination_address ( instruction );

    /* Avanzo por el camino del JUMP */
      get_second_flowchart_analysis ( level + 1 , phandle , module_base , module_limit , funcion , destination , funciones , basic_blocks , basic_block_structs , flowchart );

    /* Avanzo al siguiente basic block */
      get_second_flowchart_analysis ( level + 1 , phandle , module_base , module_limit , funcion , next_instruction + isize , funciones , basic_blocks , basic_block_structs , flowchart );

    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction + isize - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter;
      basic_block_struct -> childs = 2;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es un JUMP INCONDICIONAL */
    else if ( is_inconditional_jump ( instruction ) == TRUE )
    {
    /* Si es un JUMP RELATIVO */
      if ( is_relative_inconditional_jump ( instruction ) == TRUE )
      {
      /* Obtengo la direccion del basic block destino */
        destination = get_destination_address ( instruction );

      /* Si el destino NO es una funcion */
        if ( funciones.Find ( ( void * ) destination ) == FALSE )
        {
        /* Avanzo por el camino del JUMP */
          get_second_flowchart_analysis ( level + 1 , phandle , module_base , module_limit , funcion , destination , funciones , basic_blocks , basic_block_structs , flowchart );

        /* Salta a otro basic block */
          basic_block_struct -> childs = 1;
        }
      /* Si esta conectado con otra funcion */
        else
        {
          basic_block_struct -> childs = 0;
        }
      }
      /* Si es una JUMP TABLE */
      else if ( is_jump_table ( instruction ) == TRUE )
      {      
      /* Obtengo los punteros de la JTABLE */
        get_jtable_pointers ( phandle , instruction , module_base , module_limit , jtable_pointers );

      /* Avanzo por cada uno de los basic blocks hijos */
        for ( cont = 0 ; cont < jtable_pointers.Len () ; cont ++ )
        {
        /* Avanzo al siguiente basic block */
          get_second_flowchart_analysis ( level + 1 , phandle , module_base , module_limit , funcion , ( unsigned int ) jtable_pointers.Get ( cont ) , funciones , basic_blocks , basic_block_structs , flowchart );
        }

      /* Salta a otro basic block */
        basic_block_struct -> childs = jtable_pointers.Len ();
      }

    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction + isize - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }
  /* Si es un breakpoint */
    else if ( strcmp ( instruction , "int 3" ) == 0  )
    {
    /* Seteos del basic block */
      basic_block_struct -> size_in_bytes = next_instruction - basic_block;
      basic_block_struct -> size_in_instructions = instruction_counter - 1;
      basic_block_struct -> childs = 0;

    /* Dejo de avanzar */
      basic_block_end = TRUE;
    }

  /* Avanzo a la siguiente instruccion */
    next_instruction += isize;
  }
}

/*************************************************************/

int get_section_information ( HANDLE phandle , void *module_base , char *section_name , unsigned int *section_base , unsigned int *section_size )
{
  unsigned short sections;
  unsigned short sections_offset;
  unsigned int section_offset;
  unsigned int leidos;
  unsigned int pe_offset;
  unsigned int pe_address;
  unsigned int cont;
  char *section_address;
  char section [ 8 + 1 ];
  int ret = FALSE;

/* Offset del PE */
  read_memory ( phandle , ( void * ) ( ( unsigned int ) module_base + 0x3c ) , sizeof ( pe_offset ) , ( unsigned char * ) &pe_offset , &leidos );

/* Address del PE */
  pe_address = ( unsigned int ) module_base + pe_offset;

/* Cantidad de secciones del binario */
  read_memory ( phandle , ( void * ) ( pe_address + 6 ) , sizeof ( sections ) , ( unsigned char * ) &sections , &leidos ); 

/* Offset donde empiezan las secciones */
  read_memory ( phandle , ( void * ) ( pe_address + 0x14 ) , sizeof ( sections_offset ) , ( unsigned char * ) &sections_offset , &leidos ); 

/* Address donde empiezan las secciones del binario */
  section_address = ( char * ) ( pe_address + sections_offset + 0x18 );

/* Recorro seccion por seccion */
  for ( cont = 0 ; cont < sections ; cont ++ )
  {
  /* Inicializo el nombre de la seccion */
    memset ( section , 0 , sizeof ( section ) );

  /* Levanto el nombre de la siguiente seccion */
    read_memory ( phandle , ( void * ) &section_address [ cont * 0x28 ] , 8 , section , &leidos );

  /* Si es la seccion que estoy buscando */
//    printf ( "%s\n" , section );

  /* Si es la seccion que estoy buscando */
    if ( strcmp ( section , section_name ) == 0 )
    {
    /* Retorno la BASE de la seccion ".text" */
      read_memory ( phandle , ( void * ) &section_address [ ( cont * 0x28 ) + 0x0c ] , 4 , ( unsigned char * ) &section_offset , &leidos );

    /* Retorno el ADDRESS de la seccion */
      *section_base = ( unsigned int ) module_base + section_offset;

    /* Retorno la LONGITUD de la seccion ".text" */
      read_memory ( phandle , ( void * ) &section_address [ ( cont * 0x28 ) + 0x08 ] , 4 , ( unsigned char * ) section_size , &leidos );

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

/*************************************************************/

is_prologue_beginning ( HANDLE phandle , unsigned int address )
{
  unsigned int isize;
  char *instruction;
  int ret = FALSE;

/* Levanto la siguiente posible instruccion */
  instruction = disassembly ( phandle , address , &isize );

/* Si la instruccion PUDO ser desensamblada */
  if ( isize > 0 )
  {
  /* Si es la tipica instruccion de PADDING */
    if ( strcmp ( instruction , "mov edi,edi" ) == 0 )
    {
    /* Desensamblo la proxima instruccion */
      instruction = disassembly ( phandle , address + isize , &isize );

    /* Si es un TIPICO PROLOGO */
      if ( strcmp ( instruction , "push ebp" ) == 0 )
      {
      /* Puedo considerar que es el inicio de un PROLOGO */
        ret = TRUE;
      }
    }
  /* Si es la tipica instruccion inicial */
    else if ( strcmp ( instruction , "push ebp" ) == 0 )
    {
    /* Desensamblo la proxima instruccion */
      instruction = disassembly ( phandle , address + isize , &isize );

    /* Si es un TIPICO PROLOGO */
      if ( strcmp ( instruction , "mov ebp,esp" ) == 0 )
      {
      /* Puedo considerar que es el inicio de un PROLOGO */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

/*************************************************************/

int is_conditional_jump ( char *instruction )
{
  unsigned int cont;
  int ret = FALSE;
  char *jumps [] = { 
                     "je", "jne", "jo", "jno", "jb", "jae", "jz", "jnz", "jbe", "ja",
                     "js", "jns", "jpe", "jpo", "jl", "jge", "jle", "jg", "jecxz",
                   };
  char *jump;

/* Recorro todos los JUMPs CONDICIONALES */
  for ( cont = 0 ; cont < sizeof ( jumps ) / sizeof ( char * ) ; cont ++ )
  {
  /* Levanto el siguiente mnemonico */
    jump = jumps [ cont ];

  /* Si es este jump */
    if ( strncmp ( instruction , jump , strlen ( jump ) ) == 0 )
    {
    /* Retorno OK */
      ret = TRUE;

    /* Dejo de buscar */
      break;
    }
  }

  return ( ret );
}

/*************************************************************/

int is_inconditional_jump ( char *instruction )
{
  int ret = FALSE;

/* Si es un RET de algun tipo */
  if ( strncmp ( instruction , "jmp" , 3 ) == 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/*************************************************************/

int is_relative_inconditional_jump ( char *instruction )
{
  int ret = FALSE;

/* Si es un RET de algun tipo */
  if ( strncmp ( instruction , "jmp 0x" , 6 ) == 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/*************************************************************/

int is_basic_block_end ( char *instruction )
{
  int ret = FALSE;

/* Si es un RET de algun tipo */
  if ( ( strncmp ( instruction , "ret" , 3 ) == 0 ) || ( strncmp ( instruction , "iret" , 4 ) == 0 ) )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/*************************************************************/

int is_relative_call ( char *instruction )
{
  int ret = FALSE;
  char address [ 256 ];
  char *p;

/* Si es un CALL */
  if ( is_call ( instruction ) == TRUE )
  {
  /* Busco el primer espacio de la instruccion */
    p = strstr ( instruction , " 0x" );

  /* Si tiene un ADDRESS */
    if ( p != NULL )
    {
    /* Retorno OK */
      ret = TRUE;
    }
  }

  return ( ret );
}

/*************************************************************/

int is_call ( char *instruction )
{
  int ret = FALSE;

/* Si la instruccion empieza con un "call" */
  if ( strncmp ( instruction , "call" , 4 ) == 0 )
  {
  /* Retorno OK */
    ret = TRUE;
  }

  return ( ret );
}

/*************************************************************/

int is_jump_table ( char *instruction )
{
  int ret = FALSE;

/* Si la instruccion es un JUMP */
  if ( strncmp ( instruction , "jmp" , 3 ) == 0 )
  {
  /* Si INDEXA */
    if ( ( strchr ( instruction , '[' ) != NULL ) && ( strchr ( instruction , ']' ) != NULL ) )
    {
    /* Si usa un indice */
      if ( strstr ( instruction , "*4+0x" ) != NULL )
      {
      /* Retorno OK */
        ret = TRUE;
      }
    }
  }

  return ( ret );
}

/*************************************************************/

void get_jtable_pointers ( HANDLE phandle , char *instruction , unsigned int module_base , unsigned int module_limit , List &jtable_pointers )
{
  unsigned int destination_address;
  unsigned int jtable_base;
  unsigned int leidos;
  unsigned int pos = 0;

/* Limpio la lista donde voy a retornar los basic blocks a los cuales salta */
  jtable_pointers.Clear ();

/* Obtengo la base de la JTABLE */      
  jtable_base = get_jtable_base ( instruction );

/* Recorro puntero a puntero */
  while ( 1 )
  {
  /* Leo la siguiente entrada */
    read_memory ( phandle , ( void * ) ( jtable_base + ( pos * sizeof ( void * ) ) ) , sizeof ( void * ) , ( unsigned char * ) &destination_address , &leidos );

  /* Si pude leer */
    if ( leidos == sizeof ( void * ) )
    {
    /* Avanzo a la siguiente posicion */
      pos ++;

    /* Si el puntero esta dentro del binario */
      if ( ( module_base <= destination_address ) && ( destination_address < module_limit ) )
      {
      /* Si el puntero NO esta en la lista */
        if ( jtable_pointers.Find ( ( void * ) destination_address ) == FALSE )
        {
//          printf ( "--> %x\n" , destination_address );

        /* Agrego el puntero a la lista */
          jtable_pointers.Add ( ( void * ) destination_address );
//          printf ( "tengo que seguir por %x\n" , destination_address );
        }
      }
    /* Si el puntero esta fuera del binario */
      else
      {
      /* Dejo de buscar */
        break;
      }
    }
  /* Probablemente el puntero sea invalido */
    else
    {
    /* Salgo */
      break;
    }
  }
}

/*************************************************************/

unsigned int get_jtable_base ( char *instruction )
{
  unsigned int address = 0;
  char number [ 16 ];
  char *p1;
  char *p2;

/* Busco la base de la tabla */
  p1 = strstr ( instruction , "+0x" );
  p2 = strstr ( instruction , "]" );

/* Si pude obtener la base */
  if ( ( p1 != NULL ) && ( p2 != NULL ) )
  {
  /* Inicializo el buffer */
    memset ( number , 0 , 16 );

  /* Copio el string del numero */
    memcpy ( number , p1 + 1 , p2 - p1 - 1 );

  /* Convierto el string en un numero */
    sscanf ( number , "%x" , &address );
  }

  return ( address );
}

/*************************************************************/

unsigned int get_destination_address ( char *instruction )
{
  unsigned int address = NULL;
  char *p;

/* Busco el primer espacio de la instruccion */
  p = strstr ( instruction , " 0x" );

/* Obtengo la direccion */
  sscanf ( p , "%x" , &address );

  return ( address );
}

/*************************************************************/
