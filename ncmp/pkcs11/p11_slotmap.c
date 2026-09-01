/*
 * Token NCMP - CK-slot <-> physical-slot mapping.
 *
 * The application (or opencryptoki.conf, when the library runs under the
 * pkcsslotd API layer) numbers slots independently of the ncmpd daemon, which
 * numbers physical FX3 boards 0..PKCS11_MAX_SLOT_COUNT-1. This module bridges
 * the two so the numbering seen by the application lines up with the physical
 * token the daemon multiplexes.
 *
 * Configuration (checked in order):
 *   1. A mapping file (env NCMP_TOK_CONF, else /etc/opencryptoki/ncmptok.conf)
 *      with one "ck_slot phys_slot [label...]" entry per non-comment line.
 *   2. Otherwise an identity map offset by env NCMP_SLOT_BASE (default 0):
 *      ck_slot = NCMP_SLOT_BASE + phys_slot for every online physical slot.
 *
 * A CK slot is exposed only when its physical slot is reported online in the
 * daemon slot mask, keeping C_GetSlotList honest about token presence.
 */
#include "p11_provider.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** One CK-slot mapping entry. */
typedef struct slotmap_entry {
    int        valid;
    CK_SLOT_ID ck_slot;   /**< Application-visible slot id. */
    uint32_t   phys;      /**< Physical daemon slot index. */
    int        present;   /**< Physical slot reported online. */
    char       label[64]; /**< Token label for this slot. */
} slotmap_entry_t;

static slotmap_entry_t g_map[P11_MAX_SLOTS];
static int             g_map_count;

/** Default configuration file path when NCMP_TOK_CONF is unset. */
#define NCMP_TOK_CONF_DEFAULT "/etc/opencryptoki/ncmptok.conf"

/** Reset the map to empty. */
static void slotmap_clear(void)
{
    memset(g_map, 0, sizeof(g_map));
    g_map_count = 0;
}

/** Append one mapping entry (bounded by P11_MAX_SLOTS). */
static void slotmap_add(CK_SLOT_ID ck_slot, uint32_t phys, uint32_t slot_mask,
                        const char *label)
{
    slotmap_entry_t *e;

    if (g_map_count >= P11_MAX_SLOTS || phys >= P11_MAX_SLOTS)
        return;
    e = &g_map[g_map_count++];
    e->valid = 1;
    e->ck_slot = ck_slot;
    e->phys = phys;
    e->present = (slot_mask & (1u << phys)) ? 1 : 0;
    if (label && label[0]) {
        snprintf(e->label, sizeof(e->label), "%s", label);
    } else {
        snprintf(e->label, sizeof(e->label), "NCMP FX3 slot %u", phys);
    }
}

/**
 * @brief Parse the mapping file into the map.
 * @return Number of entries parsed (0 if the file is absent/empty).
 */
static int slotmap_parse_conf(uint32_t slot_mask)
{
    const char *path = getenv("NCMP_TOK_CONF");
    FILE *f;
    char line[256];
    int n = 0;

    if (!path)
        path = NCMP_TOK_CONF_DEFAULT;
    f = fopen(path, "re");
    if (!f)
        return 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long ck = 0, phys = 0;
        char label[64] = { 0 };
        char *p = line;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;
        /* "ck_slot phys_slot [label...]" */
        if (sscanf(p, "%lu %lu %63[^\n]", &ck, &phys, label) < 2)
            continue;
        /* Trim a trailing CR/space from the label. */
        {
            size_t l = strlen(label);
            while (l > 0 && (label[l - 1] == '\r' || label[l - 1] == ' '))
                label[--l] = '\0';
        }
        slotmap_add((CK_SLOT_ID)ck, (uint32_t)phys, slot_mask, label);
        n++;
    }
    fclose(f);
    return n;
}

void p11_slotmap_build(uint32_t slot_mask)
{
    slotmap_clear();

    if (slotmap_parse_conf(slot_mask) > 0)
        return;

    /* Identity map offset by NCMP_SLOT_BASE, exposing only online slots. */
    {
        const char *base_env = getenv("NCMP_SLOT_BASE");
        unsigned long base = base_env ? strtoul(base_env, NULL, 10) : 0;
        uint32_t phys;

        for (phys = 0; phys < P11_MAX_SLOTS; ++phys) {
            if ((slot_mask & (1u << phys)) == 0)
                continue;
            slotmap_add((CK_SLOT_ID)(base + phys), phys, slot_mask, NULL);
        }
    }
}

CK_ULONG p11_slotmap_count(int present_only)
{
    CK_ULONG n = 0;
    int i;

    for (i = 0; i < g_map_count; ++i) {
        if (!g_map[i].valid)
            continue;
        if (present_only && !g_map[i].present)
            continue;
        n++;
    }
    return n;
}

CK_ULONG p11_slotmap_list(int present_only, CK_SLOT_ID *out, CK_ULONG cap)
{
    CK_ULONG n = 0;
    int i;

    for (i = 0; i < g_map_count && n < cap; ++i) {
        if (!g_map[i].valid)
            continue;
        if (present_only && !g_map[i].present)
            continue;
        if (out)
            out[n] = g_map[i].ck_slot;
        n++;
    }
    return n;
}

CK_RV p11_slotmap_phys(CK_SLOT_ID ck_slot, uint32_t *out_phys)
{
    int i;

    for (i = 0; i < g_map_count; ++i) {
        if (g_map[i].valid && g_map[i].ck_slot == ck_slot) {
            if (!g_map[i].present)
                return CKR_TOKEN_NOT_PRESENT;
            if (out_phys)
                *out_phys = g_map[i].phys;
            return CKR_OK;
        }
    }
    return CKR_SLOT_ID_INVALID;
}

const char *p11_slotmap_label(CK_SLOT_ID ck_slot)
{
    int i;

    for (i = 0; i < g_map_count; ++i) {
        if (g_map[i].valid && g_map[i].ck_slot == ck_slot)
            return g_map[i].label;
    }
    return "NCMP FX3";
}
