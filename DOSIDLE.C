/* DosIdle
 *
 * OS/2 and Windows perfomance enhancer for CA-Clipper 5.x
 * Copyright (C) 1997-2005 by Dmitry A.Steklenev
 *
 * $Id: dosidle.c,v 1.6 2005/12/25 09:45:15 glass Exp $
 */

typedef unsigned char  BYTE;
typedef unsigned int   WORD;
typedef unsigned long  DWORD;
typedef unsigned short BOOL;

#define FALSE 0
#define TRUE  1

extern void _retl   ( BOOL );
extern int  _parl   ( int, ... );
extern int  _parinfo( int );

#ifdef SUMMER87
  extern void  _cstat ( void       );
  extern int   _keysub( int, int   );
  extern void  _retni ( int        );
  extern int   _ikey;

  BYTE _cstat_saved[3];
#else
  extern int   _upref ( char* parm );
  extern void  _errmsg( char* msgs );
  extern void *_evKbdEntry;

  void *_stKbdEntry = 0;
#endif

BOOL hooks_installed = FALSE;
BOOL initialized     = FALSE;

/*--------------------------------------------------
 * DPMI support
 *--------------------------------------------------*/

BOOL dpmi_found = FALSE;

struct _real_call {

    DWORD EDI; DWORD ESI;
    DWORD EBP; DWORD reserved;
    DWORD EBX; DWORD EDX;
    DWORD ECX; DWORD EAX;

    WORD  flags;

    WORD  ES;  WORD  DS;
    WORD  FS;  WORD  GS;
    WORD  IP;  WORD  CS;
    WORD  SP;  WORD  SS;

} real_call;

/*--------------------------------------------------
 * Release current virtual machine time-slice
 *--------------------------------------------------*/
static void _idleGenerate()
{
  static int count = 0;

  if( count++ == 50 )
  {
    count = 0;

    __asm push ax
    __asm push bx
    __asm push cx
    __asm push dx
    __asm push di
    __asm push si
    __asm push ds
    __asm push es
    __asm push bp

    if( dpmi_found )
    {
      memset( &real_call, 0, sizeof(real_call));
      real_call.EAX = 0x1680;

      __asm mov ax,0x0300
      __asm mov bh,0
      __asm mov bl,0x2F
      __asm xor cx,cx
      __asm mov di,seg real_call
      __asm mov es,di
      __asm mov di,offset real_call
      __asm int 0x31
    }
    else
    {
      __asm mov  ax,0x1680
      __asm int  0x2F
    }

    __asm pop  bp
    __asm pop  es
    __asm pop  ds
    __asm pop  si
    __asm pop  di
    __asm pop  dx
    __asm pop  cx
    __asm pop  bx
    __asm pop  ax
  }
}

/*--------------------------------------------------
 * Hook
 *--------------------------------------------------*/
void _keybHook(void)
{
  _idleGenerate();

  #ifdef SUMMER87
    __asm pop  si
    __asm pop  di
    __asm push si
    __asm push di
    __asm jmp  near ptr _cstat+3
  #else
    __asm mov  sp,bp
    __asm pop  bp
    __asm jmp  dword ptr ss:_stKbdEntry
  #endif
}

#ifdef SUMMER87
/*--------------------------------------------------
 * Replacement of the INKEYTRAP(0)
 *--------------------------------------------------*/
void pascal DINKEYTRAP(void)
{
  while( !_keysub(7,7));
  _retni( _ikey );
}
#endif

/*--------------------------------------------------
 * Initialize
 *--------------------------------------------------*/
void pascal DOSIDLE(void)
{
  if( !initialized )
  {
    __asm mov ax, 0x1686
    __asm int 0x2F
    __asm or  ax,ax
    __asm jne not_dpmi_found

    dpmi_found = TRUE;

not_dpmi_found:

    #ifndef SUMMER87
      if( _upref( "INFO" ) == 0 )
      {
        _errmsg( "OS/2 & Windows perfomance enhancer for CA-Clipper Version 1.4\r\n"
                 "Copyright (C) 1997-2005 by Dmitry A.Steklenev. " );

        if( dpmi_found ) {
          _errmsg( "*** USED DPMI ***\r\n" );
        } else {
          _errmsg( "\r\n" );
        }
      }
    #endif
    initialized = TRUE;
  }

  _retl( hooks_installed );

  if( _parinfo(0) == 0 || !(_parinfo(1) & 4) || _parl(1) == TRUE  ) {
    if( !hooks_installed )
    {
      #ifdef SUMMER87
        if( !_cstat_saved[0] )
        {
          __asm lea  si,_cstat
          __asm lea  di,_cstat_saved
          __asm mov  al, cs:byte ptr [si]
          __asm mov  byte ptr [di], al
          __asm inc  si
          __asm inc  di
          __asm mov  ax, cs:word ptr [si]
          __asm mov  word ptr [di], ax

          __asm lea  bx,_cstat
          __asm mov  cs:byte ptr [bx],0E9h
          __asm lea  dx,_keybHook
          __asm lea  cx,_cstat
          __asm sub  dx,cx
          __asm sub  dx,3
          __asm inc  bx
          __asm mov  cs:word ptr [bx],dx
        }
      #else
        if( !_stKbdEntry )
        {
          _stKbdEntry = _evKbdEntry;
          _evKbdEntry = (void*)&_keybHook;
        }
      #endif
      hooks_installed = TRUE;
    }
  } else {
    if(  hooks_installed )
    {
      #ifdef SUMMER87
        if( _cstat_saved[0] )
        {
          __asm lea  di,_cstat
          __asm lea  si,_cstat_saved
          __asm mov  al, byte ptr [si]
          __asm mov  cs:byte ptr [di], al
          __asm inc  si
          __asm inc  di
          __asm mov  ax, word ptr [si]
          __asm mov  cs:word ptr [di], ax

          _cstat_saved[0] = 0;
        }
      #else
        if( _stKbdEntry )
        {
          _evKbdEntry = _stKbdEntry;
          _stKbdEntry = 0;
        }
      #endif
      hooks_installed = FALSE;
    }
  }
}
