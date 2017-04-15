AC_PREREQ([2.68])
AC_INIT([Seren], [0.0.21], [mywing81@gmail.com])
AC_CONFIG_SRCDIR([common.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_LANG([C])

CFLAGS="$CFLAGS -Wall -W -Wconversion"

# Checks for libraries.
AC_CHECK_LIB([m], [sin], [], AC_MSG_ERROR([cannot find libm]))
AC_CHECK_LIB([asound], [snd_pcm_open], [], AC_MSG_ERROR([cannot find libasound]))
AC_CHECK_LIB([opus], [opus_encoder_create], [], AC_MSG_ERROR([cannot find libopus]))
AC_CHECK_LIB([ogg], [ogg_stream_init], [], AC_MSG_ERROR([cannot find libogg]))
AC_CHECK_LIB([gmp], [__gmpz_init], [], AC_MSG_ERROR([cannot find libgmp]))

# Checks for header files.
AC_CHECK_HEADERS([locale.h stddef.h stdint.h stdlib.h string.h unistd.h fcntl.h], [], AC_MSG_ERROR([missing header]))
AC_CHECK_HEADERS([sys/time.h sys/socket.h netinet/in.h arpa/inet.h netdb.h], [], AC_MSG_ERROR([missing header]))
AC_CHECK_HEADERS([alsa/asoundlib.h], [], AC_MSG_ERROR([cannot find asoundlib.h]))
AC_CHECK_HEADERS([opus/opus.h], [], AC_MSG_ERROR([cannot find opus/opus.h]))
AC_CHECK_HEADERS([ogg/ogg.h], [], AC_MSG_ERROR([cannot find ogg/ogg.h]))
AC_CHECK_HEADERS([gmp.h], [], AC_MSG_ERROR([cannot find gmp.h]))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyname gettimeofday inet_ntoa memmove memset mkdir mkfifo setlocale socket strdup strchr strstr strerror])

# Options
AC_ARG_WITH([ncurses],
    [AS_HELP_STRING([--without-ncurses], [disable support for ncurses])],
    [],
    [with_ncurses=yes])
AS_IF([test "x$with_ncurses" != xno],
    [AC_CHECK_LIB([ncursesw], [initscr], [], AC_MSG_ERROR([cannot find libncursesw]))
     AC_CHECK_HEADERS([ncursesw/ncurses.h ncurses.h])
     AS_IF([test "$ac_cv_header_ncursesw_ncurses_h" = "no" -a "$ac_cv_header_ncurses_h" = "no"],
         [AC_MSG_ERROR([cannot find ncursesw/ncurses.h or ncurses.h])])
    ])

AC_ARG_ENABLE([default-pulse],
    [AS_HELP_STRING([--enable-default-pulse], [set default device to 'pulse'])],
    [],
    [enable_default_pulse=no])
AS_IF([test "x$enable_default_pulse" != xno],
    [AC_DEFINE([DEFAULT_PULSE], [1], [Define to 1 to set default device to 'pulse'])]
)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AC_MSG_NOTICE([
-----------------------------------------------------------
  $PACKAGE_STRING:  Automatic configuration OK.
-----------------------------------------------------------

  Prefix:        '${prefix}'
  Compiler:      '${CC} ${CFLAGS} ${CPPFLAGS}'

  ncurses:       '${with_ncurses}'
  default-pulse: '${enable_default_pulse}'

  Type "make" to compile
  Type "make install" to install
  Type "make uninstall" to uninstall
])
