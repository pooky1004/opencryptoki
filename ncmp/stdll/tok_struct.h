/*
 * Token NCMP - STDLL identity constants.
 *
 * Mirrors the pattern used by opencryptoki's other tokens (e.g. soft_stdll's
 * tok_struct.h). When integrated into the opencryptoki tree this header backs
 * the `token_spec_t token_specific` definition consumed by the API layer.
 */
#ifndef NCMP_TOK_STRUCT_H
#define NCMP_TOK_STRUCT_H

#ifndef NCMP_CONFIG_PATH
#ifndef CONFIG_PATH
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif
#define NCMP_CONFIG_PATH CONFIG_PATH "/ncmptok"
#endif

/** On-disk token data subdirectory name. */
#define NCMP_TOKEN_SUBDIR "ncmptok"

/** Human-readable token/manufacturer identity (padded/space-filled at use). */
#define NCMP_TOKEN_LABEL      "Token NCMP"
#define NCMP_TOKEN_MANUF      "DYST"
#define NCMP_TOKEN_MODEL      "FX3-USB"

#endif /* NCMP_TOK_STRUCT_H */
