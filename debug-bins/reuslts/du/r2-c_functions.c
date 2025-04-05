// sym._init
void sym._init(void)

{
    ulong auStack_10[2];

    if (_reloc.__gmon_start__ != NULL)
    {
        *(*0x20 + -8 + -8) = 0x1016;
        (*_reloc.__gmon_start__)();
    }
    return;
}

// main
uint8_t main(uint32_t param_1, int64_t *param_2)

{
    int64_t iVar1;
    uint16_t uVar2;
    uint8_t *puVar3;
    char *pcVar4;
    char cVar5;
    int32_t iVar6;
    uint uVar7;
    uint32_t uVar8;
    int64_t iVar9;
    int64_t iVar10;
    ulong uVar11;
    ulong uVar12;
    ulong uVar13;
    ulong uVar14;
    int64_t *piVar15;
    char **ppcVar16;
    uchar *puVar17;
    uint64_t *puVar18;
    int32_t *piVar19;
    char **ppcVar20;
    uchar *puVar21;
    uchar *puVar22;
    uchar *puVar23;
    char *pcVar24;
    ulong *puVar25;
    uint *puVar26;
    char **ppcVar27;
    char cVar28;
    uint64_t uVar29;
    char **ppcVar30;
    uchar *puVar31;
    uchar *puVar32;
    uchar *puVar33;
    uchar *puVar34;
    uchar *puVar35;
    uchar *puVar36;
    uchar *puVar37;
    uchar *puVar38;
    uchar *puVar39;
    uchar *puVar40;
    uchar *puVar41;
    uchar *puVar42;
    uchar *puVar43;
    uchar *puVar44;
    uchar *puVar45;
    uchar *puVar46;
    uchar *puVar47;
    uchar *puVar48;
    uchar *puVar49;
    uchar *puVar50;
    uchar *puVar51;
    uchar *puVar52;
    uchar *puVar53;
    uchar *puVar54;
    uchar *puVar55;
    uchar *puVar56;
    uchar *puVar57;
    uchar *puVar58;
    uchar *puVar59;
    uchar *puVar60;
    uchar *puVar61;
    uchar *puVar62;
    uchar *puVar63;
    uchar *puVar64;
    uchar *puVar65;
    uchar *puVar66;
    uchar *puVar67;
    uchar *puVar68;
    uchar *puVar69;
    uchar *puVar70;
    uchar *puVar71;
    uchar *puVar74;
    uchar *puVar75;
    uchar *puVar76;
    uchar *puVar77;
    uchar *puVar78;
    uchar *puVar79;
    uchar *puVar80;
    uchar *puVar81;
    uchar *puVar82;
    uchar *puVar83;
    uchar *puVar84;
    uchar *puVar85;
    uchar *puVar86;
    uchar *puVar87;
    uchar *puVar88;
    uchar *puVar89;
    uchar *puVar90;
    uchar *puVar91;
    uchar *puVar92;
    uchar *puVar93;
    uchar *puVar94;
    uchar *puVar95;
    uchar *puVar96;
    uchar *puVar97;
    uchar *puVar98;
    uchar *puVar99;
    uchar *puVar100;
    uchar *puVar101;
    uchar *puVar102;
    char **ppcVar103;
    uint64_t uVar104;
    char **ppcVar105;
    char **ppcVar106;
    int64_t iVar107;
    uint32_t *puVar108;
    code *pcVar109;
    char **ppcVar110;
    char **ppcVar111;
    uint32_t uVar112;
    char *pcVar113;
    uint8_t **ppuVar114;
    int64_t *piVar115;
    int64_t in_FS_OFFSET;
    bool bVar116;
    uint8_t uVar117;
    uint8_t uVar118;
    bool bVar119;
    char **ppcVar120;
    char **ppcVar121;
    ulong uStack_1d0;
    char **ppcStack_1c8;
    char **ppcStack_1c0;
    int64_t *piStack_1b8;
    char *pcStack_1b0;
    uint32_t uStack_1a8;
    uint8_t uStack_1a2;
    uint8_t uStack_1a1;
    char *pcStack_1a0;
    int64_t iStack_198;
    ulong uStack_190;
    char **ppcStack_188;
    ulong uStack_180;
    ulong uStack_178;
    ulong uStack_170;
    ulong uStack_168;
    char **ppcStack_160;
    ulong uStack_158;
    char **ppcStack_150;
    uchar *puStack_148;
    ulong uStack_140;
    uint32_t uStack_134;
    uint32_t uStack_130;
    int32_t iStack_12c;
    code *pcStack_128;
    char **ppcStack_120;
    char *pcStack_118;
    ulong uStack_110;
    char **ppcStack_108;
    char **ppcStack_100;
    char **ppcStack_f8;
    char **ppcStack_f0;
    int64_t aiStack_e8[2];
    char *apcStack_d8[19];
    int64_t iStack_40;
    uchar *puVar72;
    uchar *puVar73;

    iVar107 = *param_2;
    iStack_40 = *(in_FS_OFFSET + 0x28);
    aiStack_e8[1] = 0;
    aiStack_e8[0] = 0x12f7e;
    if (iVar107 == 0)
    {
        uStack_1d0 = 0x430d;
        sym.imp.fwrite("A NULL argv[0] was passed through an exec system call.\n", 1, 0x37, *_reloc.stderr);
        // WARNING: Subroutine does not return
        *(&stack0xfffffffffffffe38 + -8) = 0x4312;
        sym.imp.abort();
    }
    uStack_1d0 = 0x1d5d;
    iVar9 = sym.imp.strrchr(iVar107, 0x2f);
    puVar17 = &stack0xfffffffffffffe38;
    if (iVar9 != 0)
    {
        iVar1 = iVar9 + 1;
        iVar10 = iVar1 - iVar107;
        puVar17 = &stack0xfffffffffffffe38;
        if (iVar10 != 6 && SBORROW8(iVar10, 6) == iVar10 + -6 < 0)
        {
            *(&stack0xfffffffffffffe38 + -8) = 0x1d8a;
            iVar6 = sym.imp.strncmp(iVar9 + -6, "/.libs/", 7);
            puVar17 = *0x20 + -0x1c8;
            if (iVar6 == 0)
            {
                iVar107 = iVar1;
                *(*0x20 + -0x1d0) = 0x1da5;
                iVar6 = sym.imp.strncmp(iVar1, 0x13032, 3);
                puVar17 = &stack0xfffffffffffffe38;
                if (iVar6 == 0)
                {
                    iVar107 = iVar9 + 4;
                    *_reloc.program_invocation_short_name = iVar9 + 4;
                    puVar17 = &stack0xfffffffffffffe38;
                }
            }
        }
    }
    *0x18280 = iVar107;
    *_reloc.program_invocation_name = iVar107;
    *(puVar17 + -8) = 0x1de4;
    sym.imp.setlocale(6, 0x12f50);
    puVar31 = puVar17;
    *(puVar17 + -8) = 0x1df3;
    sym.imp.bindtextdomain("coreutils", "/usr/share/locale");
    puVar32 = puVar31;
    *(puVar31 + -8) = 0x1e02;
    sym.imp.textdomain("coreutils");
    puVar33 = puVar32;
    *(puVar32 + -8) = 0x1e0e;
    sym.atexit(sym.close_stdout);
    puVar34 = puVar33;
    *(puVar33 + -8) = 0x1e13;
    *0x18250 = sym.new_exclude();
    puVar35 = puVar34;
    *(puVar34 + -8) = 0x1e26;
    uVar11 = sym.imp.getenv("DU_BLOCK_SIZE");
    *(puVar35 + -8) = 0x1e2e;
    sym.human_options.constprop.0(uVar11);
    puStack_148 = &stack0xfffffffffffffef0;
    uStack_178 = (uStack_178 >> 8) << 8;
    uStack_140._0_4_ = 0x10;
    uStack_158._0_4_ = 8;
    pcStack_1a0 = NULL;
    uStack_170._0_1_ = 1;
    uStack_168 = (uStack_168 >> 8) << 8;
    puVar17 = puVar35;
code_r0x00001e70:
    do
    {
        uStack_110 = CONCAT44(uStack_110._4_4_, 0xffffffff);
        *(puVar17 + -8) = 0x1e92;
        iVar6 = sym.imp.getopt_long(param_1, param_2, "0abd:chHklmst:xB:DLPSX:", 0x176c0);
        puVar61 = puVar17;
        puVar82 = puVar17;
        puVar48 = puVar17;
        puVar39 = puVar17;
        puVar38 = puVar17;
        puVar17 = puVar17;
        if (iVar6 == -1)
        {
            if (uStack_170 == 0)
                goto code_r0x00004280;
            if (*0x1824b == '\0')
            {
                if (uStack_168 == '\0')
                {
                    if (uStack_178 != '\0')
                    {
                    code_r0x0000321f:
                        *0x18028 = NULL;
                    }
                }
                else if (uStack_178 != '\0')
                {
                    if (*0x18028 == NULL)
                    {
                        puVar60 = puVar17;
                        *(puVar17 + -8) = 0x3201;
                        uVar11 = sym.imp.dcgettext(0, "warning: summarizing is the same as using --max-depth=0", 5);
                        *(puVar60 + -8) = 0x320f;
                        sym.imp.error(0, 0, uVar11);
                        puVar82 = puVar60;
                        puVar48 = puVar60;
                        if (*0x18028 == NULL)
                            goto code_r0x0000321f;
                    }
                    ppcVar16 = *0x18028;
                    puVar49 = puVar48;
                    *(puVar48 + -8) = 0x2526;
                    uVar11 = sym.imp.dcgettext(0, "warning: summarizing conflicts with --max-depth=%td", 5);
                    *(puVar49 + -8) = 0x2537;
                    sym.imp.error(0, 0, uVar11, ppcVar16);
                    puVar61 = puVar49;
                    if (iStack_40 != *(in_FS_OFFSET + 0x28))
                        goto code_r0x0000254a;
                    goto code_r0x00003c47;
                }
            }
            else if (uStack_178 != '\0')
            {
                puVar83 = puVar17;
                *(puVar17 + -8) = 0x3c26;
                uVar11 = sym.imp.dcgettext(0, "cannot both summarize and show all entries", 5);
                *(puVar83 + -8) = 0x3c34;
                sym.imp.error(0, 0, uVar11);
                puVar61 = puVar83;
                if (iStack_40 == *(in_FS_OFFSET + 0x28))
                    goto code_r0x00003c47;
                goto code_r0x0000254a;
            }
            if (*0x18271 != '\0')
            {
                if (*0x1824a != '\0')
                {
                    *(puVar82 + -8) = 0x3c00;
                    uVar11 = sym.imp.dcgettext(0,
                                               "warning: options --apparent-size and -b are ineffective with --inodes",
                                               5);
                    *(puVar82 + -8) = 0x3c0e;
                    sym.imp.error(0, 0, uVar11);
                    puVar82 = puVar82;
                }
                *0x18278 = 1;
            }
            if (*0x18270 == '\0')
                goto code_r0x000023d7;
            pcVar113 = *0x18230;
            if (*0x18230 != NULL)
                goto code_r0x000023c2;
            *(puVar82 + -8) = 0x3a2d;
            pcVar113 = sym.imp.getenv("TIME_STYLE");
            puVar17 = puVar82;
            *0x18230 = pcVar113;
            if (pcVar113 != NULL)
            {
                *(puVar82 + -8) = 0x3a4f;
                iVar6 = sym.imp.strcmp(pcVar113, "locale");
                puVar17 = puVar82 + 0;
                puVar79 = puVar82 + 0;
                if (iVar6 != 0)
                {
                    pcVar24 = pcVar113;
                    pcVar4 = *0x18230;
                    if (*pcVar113 != '+')
                        break;
                    *(puVar82 + -8) = 0x41e4;
                    puVar17 = sym.imp.strchr(pcVar113, 10);
                    puVar82 = puVar82;
                    if (puVar17 == NULL)
                        goto code_r0x000023cc;
                    *puVar17 = 0;
                    goto code_r0x000023c2;
                }
            }
            pcVar113 = "long-iso";
            *0x18230 = "long-iso";
            goto code_r0x000036e2;
        }
        if (iVar6 != 0x87 && SBORROW4(iVar6, 0x87) == iVar6 + -0x87 < 0)
        {
        code_r0x00001ed0:
            uStack_170._0_1_ = 0;
            puVar17 = puVar17;
            goto code_r0x00001e70;
        }
        if (iVar6 == 0x2f || SBORROW4(iVar6, 0x2f) != iVar6 + -0x2f < 0)
        {
            if (iVar6 == -0x83)
            {
                *(puVar17 + -8) = 0x22b1;
                uVar11 = sym.proper_name_lite("Jim Meyering", "Jim Meyering");
                puVar40 = puVar17;
                *(puVar17 + -8) = 0x22c3;
                uVar12 = sym.proper_name_lite("Paul Eggert", "Paul Eggert");
                puVar41 = puVar40;
                *(puVar40 + -8) = 0x22d5;
                uVar13 = sym.proper_name_lite("David MacKenzie", "David MacKenzie");
                puVar42 = puVar41;
                *(puVar41 + -8) = 0x22eb;
                uVar14 = sym.proper_name_lite("Torbjorn Granlund", "Torbjörn Granlund");
                *(puVar42 + -8) = uVar14;
                *(puVar42 + -0x10) = 0;
                *(puVar42 + -0x18) = uVar11;
                *(puVar42 + -0x20) = uVar12;
                uVar11 = *_reloc.stdout;
                *(puVar42 + -0x28) = 0x231e;
                sym.version_etc.constprop.0(uVar11, 0x12d66, "GNU coreutils", 0x130ea, uVar14, uVar13);
                // WARNING: Subroutine does not return
                *(puVar42 + -8) = 0x2329;
                sym.imp.exit(0);
            }
            if (iVar6 != -0x82)
                goto code_r0x00001ed0;
            if (iStack_40 == *(in_FS_OFFSET + 0x28))
            {
                // WARNING: Subroutine does not return
                *(puVar17 + -8) = 0x3984;
                sym.usage(0);
            }
            goto code_r0x0000254a;
        }
        // switch table (88 cases) at 0x14f90
        switch (iVar6 + -0x30)
        {
        case 0:
            *0x18258 = 1;
            break;
        default:
            goto code_r0x00001ed0;
        case 0x12:
            goto code_r0x00001ee5;
        case 0x14:
        case 0x18:
            uStack_140 = CONCAT44(uStack_140._4_4_, 0x11);
            break;
        case 0x1c:
            uStack_140 = CONCAT44(uStack_140._4_4_, 2);
            break;
        case 0x20:
            uStack_140 = CONCAT44(uStack_140._4_4_, 0x10);
            break;
        case 0x23:
            *0x1823c = '\x01';
            break;
        case 0x28:
            ppcStack_188 = *_reloc.optarg;
            ppcVar16 = ppcStack_188;
            uStack_180 = *0x18250;
            pcStack_128 = sym.add_exclude;
            *(puVar17 + -8) = 0x1f70;
            iVar6 = sym.imp.strcmp(ppcVar16, 0x12ea9);
            ppcVar16 = ppcStack_188;
            if (iVar6 == 0)
            {
                ppcVar16 = uStack_180;
                puVar3 = *_reloc.stdin;
                *(puVar17 + -8) = 0x234b;
                iVar6 = sym.add_exclude_fp.constprop.0(ppcVar16, puVar3, 10, &stack0xfffffffffffffed8);
                puVar43 = puVar17;
            code_r0x00001ff5:
                puVar17 = puVar43;
                if (iVar6 == 0)
                    break;
            }
            else
            {
                *(puVar17 + -8) = 0x1f8b;
                iVar107 = sym.rpl_fopen.constprop.0(ppcVar16, "re");
                puVar43 = puVar17 + 0;
                if (iVar107 != 0)
                {
                    ppcVar16 = uStack_180;
                    iStack_198 = iVar107;
                    *(puVar17 + -8) = 0x1fb2;
                    uVar7 = sym.add_exclude_fp.constprop.0(ppcVar16, iVar107, 10, &stack0xfffffffffffffed8);
                    uStack_190 = CONCAT44(uStack_190._4_4_, uVar7);
                    puVar36 = puVar17 + 0;
                    *(puVar17 + 0 + -8) = 0x1fbd;
                    ppcStack_188 = sym.imp.__errno_location();
                    iVar107 = iStack_198;
                    uStack_180 = CONCAT44(uStack_180._4_4_, *ppcStack_188);
                    *(puVar36 + -8) = 0x1fda;
                    iVar6 = sym.rpl_fclose(iVar107);
                    puVar43 = puVar36;
                    if (-1 < iVar6)
                    {
                        iVar6 = uStack_190;
                        *ppcStack_188 = uStack_180;
                        goto code_r0x00001ff5;
                    }
                }
            }
            pcVar113 = *_reloc.optarg;
            *(puVar43 + -8) = 0x200c;
            uStack_170 = sym.quotearg_n_style_colon.constprop.0(pcVar113);
            puVar37 = puVar43;
            *(puVar43 + -8) = 0x2018;
            puVar26 = sym.imp.__errno_location();
            uVar11 = uStack_170;
            uVar7 = *puVar26;
            *(puVar37 + -8) = 0x2031;
            sym.imp.error(0, uVar7, 0x12fe5, uVar11);
            puVar17 = puVar37;
            uStack_170._0_1_ = 0;
            break;
        case 0x31:
            *0x1824b = '\x01';
            puVar17 = puVar17;
            break;
        case 0x32:
            *0x1824a = '\x01';
            *0x18274 = 0;
            *0x18278 = 1;
            puVar17 = puVar17;
            break;
        case 0x33:
            *0x18249 = '\x01';
            puVar17 = puVar17;
            break;
        case 0x34:
            pcVar113 = *_reloc.optarg;
            *(puVar17 + -8) = 0x223e;
            iVar6 = sym.xstrtoimax.constprop.0(pcVar113, &stack0xfffffffffffffef8, 0x12f50);
            if (iVar6 == 0)
            {
                *0x18028 = ppcStack_108;
                uStack_168 = CONCAT71(uStack_168._1_7_, 1);
                puVar17 = puVar17;
            }
            else
            {
                pcVar113 = *_reloc.optarg;
                *(puVar17 + -8) = 0x432a;
                uStack_170 = sym.quotearg_n_options.constprop.0(0, pcVar113, 0x18040);
                puVar97 = puVar17;
                *(puVar17 + -8) = 0x4344;
                uVar12 = sym.imp.dcgettext(0, "invalid maximum depth %s", 5);
                uVar11 = uStack_170;
                *(puVar97 + -8) = 0x4359;
                sym.imp.error(0, 0, uVar12, uVar11);
                uStack_170._0_1_ = 0;
                puVar17 = puVar97;
            }
            break;
        case 0x38:
            *0x18274 = 0xb0;
            *0x18278 = 1;
            puVar17 = puVar17;
            break;
        case 0x3b:
            *0x18278 = 0x400;
            *0x18274 = 0;
            puVar17 = puVar17;
            break;
        case 0x3c:
            *0x18248 = '\x01';
            puVar17 = puVar17;
            break;
        case 0x43:
            uStack_178 = CONCAT71(uStack_178._1_7_, 1);
            puVar17 = puVar17;
            break;
        case 0x44:
            pcVar113 = *_reloc.optarg;
            *(puVar17 + -8) = 0x216b;
            iVar6 = sym.xstrtoimax.constprop.0(pcVar113, 0x18240, "kKmMGTPEZYRQ0");
            puVar61 = puVar17;
            if (iVar6 != 0)
            {
                if (iStack_40 == *(in_FS_OFFSET + 0x28))
                {
                    uVar7 = uStack_110;
                    pcVar113 = *_reloc.optarg;
                    // WARNING: Subroutine does not return
                    *(puVar17 + -8) = 0x440a;
                    sym.xstrtol_fatal.constprop.0(iVar6, uVar7, 0x74, pcVar113);
                }
                goto code_r0x0000254a;
            }
            puVar17 = puVar17;
            if ((*0x18240 != NULL) || (puVar17 = puVar17, **_reloc.optarg != '-'))
                break;
            *(puVar17 + -8) = 0x21a7;
            uVar11 = sym.imp.dcgettext(0, "invalid --threshold argument \'-0\'", 5);
            puVar61 = puVar17 + 0;
            if (iStack_40 != *(in_FS_OFFSET + 0x28))
                goto code_r0x0000254a;
            *(puVar17 + -8) = 0x21cb;
            sym.imp.error(1, 0, uVar11);
            puVar39 = puVar17 + 0;
        case 0x3d:
            *0x18278 = 0x100000;
            *0x18274 = 0;
            puVar17 = puVar39;
            break;
        case 0x48:
            uStack_158 = CONCAT44(uStack_158._4_4_, 0x48);
            puVar17 = puVar17;
            break;
        case 0x50:
            *0x1824a = '\x01';
            puVar17 = puVar17;
            break;
        case 0x51:
            pcVar113 = *_reloc.optarg;
            *(puVar17 + -8) = 0x213d;
            sym.add_exclude(*0x18250, pcVar113, 0x10000000);
            puVar17 = puVar17;
            break;
        case 0x52:
            pcStack_1a0 = *_reloc.optarg;
            puVar17 = puVar17;
            break;
        case 0x53:
            *0x18274 = 0x90;
            *0x18278 = 1;
            puVar17 = puVar17;
            break;
        case 0x55:
            *0x18270 = '\x01';
            pcVar113 = *_reloc.optarg;
            uVar8 = 0;
            if (pcVar113 != NULL)
            {
                *(puVar17 + -8) = 0x20c2;
                iVar107 = sym.__xargmatch_internal.constprop.0("--time", pcVar113, 0x17680, 0x151e0, sym.__argmatch_die);
                puVar38 = puVar17;
                uVar8 = *(iVar107 * 4 + 0x151e0);
            }
            *0x18238 = uVar8;
            *(puVar38 + -8) = 0x20de;
            uVar11 = sym.imp.getenv(0x12ed0);
            *(puVar38 + -8) = 0x20e6;
            *0x18268 = sym.tzalloc(uVar11);
            puVar17 = puVar38;
            break;
        case 0x56:
            *0x18230 = *_reloc.optarg;
            puVar17 = puVar17;
            break;
        case 0x57:
            *0x18271 = '\x01';
            puVar17 = puVar17;
        }
    } while (true);
    do
    {
        *0x18230 = pcVar4;
        pcVar113 = pcVar24;
        *(puVar79 + -8) = 0x3a87;
        iVar6 = sym.imp.strncmp(pcVar113, "posix-", 6);
        puVar82 = puVar79;
        pcVar24 = pcVar113 + 6;
        pcVar4 = pcVar113 + 6;
    } while (iVar6 == 0);
code_r0x000023c2:
    puVar17 = puVar82;
    if (*pcVar113 == '+')
    {
    code_r0x000023cc:
        *0x18260 = pcVar113 + 1;
    }
    else
    {
    code_r0x000036e2:
        *(puVar17 + -8) = 0x3709;
        iVar107 = sym.__xargmatch_internal.constprop.0(0x130f9, pcVar113, 0x17660, 0x151c8);
        puVar82 = puVar17;
        uVar8 = *(iVar107 * 4 + 0x151c8);
        if (uVar8 == 1)
        {
            *0x18260 = "%Y-%m-%d %H:%M";
        }
        else
        {
            if (uVar8 == 2)
                goto code_r0x00003957;
            if ((uVar8 & uVar8) == 0)
            {
                *0x18260 = "%Y-%m-%d %H:%M:%S.%N %z";
            }
        }
    }
code_r0x000023d7:
    do
    {
        puVar108 = _reloc.optind;
        uVar8 = *puVar108;
        if (pcStack_1a0 == NULL)
            goto code_r0x00003255;
        if (param_1 != uVar8 && SBORROW4(param_1, uVar8) == param_1 - uVar8 < 0)
        {
            iVar107 = param_2[uVar8];
            *(puVar82 + -8) = 0x4226;
            uVar11 = sym.quotearg_n_options.constprop.0(0, iVar107, 0x18040);
            puVar94 = puVar82;
            *(puVar82 + -8) = 0x423c;
            uVar12 = sym.imp.dcgettext(0, "extra operand %s", 5);
            puVar95 = puVar94;
            *(puVar94 + -8) = 0x424d;
            sym.imp.error(0, 0, uVar12, uVar11);
            puVar96 = puVar95;
            *(puVar95 + -8) = 0x4260;
            uVar12 = sym.imp.dcgettext(0, "file operands cannot be combined with --files0-from", 5);
            uVar11 = *_reloc.stderr;
            *(puVar96 + -8) = 0x4280;
            sym.imp.__fprintf_chk(uVar11, 2, 0x12f06, uVar12);
            puVar61 = puVar96;
        code_r0x00004280:
            if (iStack_40 == *(in_FS_OFFSET + 0x28))
            {
            code_r0x00003c47:
                // WARNING: Subroutine does not return
                *(puVar61 + -8) = 0x3c51;
                sym.usage(1);
            }
            goto code_r0x0000254a;
        }
        pcVar113 = pcStack_1a0;
        *(puVar82 + -8) = 0x240c;
        iVar6 = sym.imp.strcmp(pcVar113, 0x12ea9);
        puVar47 = puVar82;
        ppuVar114 = _reloc.stdin;
        if (iVar6 == 0)
        {
        code_r0x00002562:
            puVar3 = *ppuVar114;
            *(puVar47 + -8) = 0x256a;
            piVar15 = sym.argv_iter_init_stream(puVar3);
            puVar61 = puVar47;
            uVar118 = uStack_170;
            goto code_r0x00002574;
        }
        puVar3 = *ppuVar114;
        *(puVar82 + -8) = 0x2426;
        iVar6 = sym.imp.fileno(puVar3);
        puVar44 = puVar82 + 0;
        puVar75 = puVar82 + 0;
        if (iVar6 == 1)
        {
            *(puVar82 + -8) = 0x3a10;
            iVar6 = sym.imp.dup2(0, 0);
            puVar78 = puVar82;
            puVar75 = puVar82;
            if (iVar6 != 0)
            {
                uVar117 = false;
                uVar118 = false;
                goto code_r0x000039d7;
            }
            param_1 = 0;
            uVar117 = 0;
            uVar118 = 0;
        code_r0x000038af:
            pcVar113 = pcStack_1a0;
            *(puVar75 + -8) = 0x38c5;
            uStack_168 = sym.imp.freopen(pcVar113, "r", puVar3);
            puVar76 = puVar75;
        code_r0x000038cc:
            *(puVar76 + -8) = 0x38d1;
            puVar108 = sym.imp.__errno_location();
            puVar47 = puVar76;
            puVar46 = puVar76;
            uStack_178 = CONCAT44(uStack_178._4_4_, *puVar108);
            if (uVar117 != 0)
            {
            code_r0x000024ce:
                *(puVar46 + -8) = 0x24d8;
                sym.imp.close(2);
                puVar47 = puVar46;
            }
            if (uVar118 != 0)
                goto code_r0x000039a5;
        }
        else
        {
            if (iVar6 == 2)
            {
                uVar117 = false;
            }
            else
            {
                if (iVar6 == 0)
                {
                    uVar118 = 0;
                    uVar117 = 0;
                    param_1 = 0;
                    goto code_r0x000038af;
                }
                *(puVar82 + -8) = 0x244f;
                iVar6 = sym.imp.dup2(2, 2);
                puVar44 = puVar82 + 0;
                uVar117 = iVar6 != 2;
            }
            puVar45 = puVar44;
            *(puVar44 + -8) = 0x2464;
            iVar6 = sym.imp.dup2(1, 1);
            uVar118 = iVar6 + -1 != 0;
            param_1 = 0;
            *(puVar45 + -8) = 0x2477;
            iVar6 = sym.imp.dup2(0, 0);
            puVar75 = puVar45;
            puVar78 = puVar45;
            if (iVar6 != 0)
            {
            code_r0x000039d7:
                *(puVar78 + -8) = 0x39de;
                param_1 = sym.protect_fd(0);
                puVar75 = puVar78;
                puVar76 = puVar78;
                if (param_1 != '\0')
                    goto code_r0x0000247f;
                param_1 = uStack_170;
                uStack_168 = NULL;
                goto code_r0x000038cc;
            }
        code_r0x0000247f:
            if (uVar118 == false)
            {
            code_r0x00002499:
                if (uVar117 != false)
                {
                    *(puVar75 + -8) = 0x24ab;
                    uVar117 = sym.protect_fd(2);
                    if (uVar117 == 0)
                    {
                        *(puVar75 + -8) = 0x24ba;
                        puVar108 = sym.imp.__errno_location();
                        puVar46 = puVar75 + 0;
                        uStack_168 = NULL;
                        uStack_178 = CONCAT44(uStack_178._4_4_, *puVar108);
                        goto code_r0x000024ce;
                    }
                }
                goto code_r0x000038af;
            }
            *(puVar75 + -8) = 0x248e;
            uVar118 = sym.protect_fd(1);
            if (uVar118 != 0)
                goto code_r0x00002499;
            *(puVar75 + -8) = 0x3989;
            puVar108 = sym.imp.__errno_location();
            puVar46 = puVar75 + 0;
            puVar47 = puVar75 + 0;
            uVar8 = *puVar108;
            uStack_178 = CONCAT44(uStack_178._4_4_, uVar8);
            if (uVar117 != false)
            {
                uVar118 = uVar117 & 0xff;
                uStack_168 = NULL;
                goto code_r0x000024ce;
            }
            uStack_168 = uVar8 ^ uVar8;
        code_r0x000039a5:
            *(puVar47 + -8) = 0x39af;
            sym.imp.close(1);
            puVar47 = puVar47;
        }
        if (param_1 != '\0')
        {
            *(puVar47 + -8) = 0x39cd;
            sym.imp.close(0);
            puVar47 = puVar47;
        }
        if (uStack_168 != NULL)
            goto code_r0x00002562;
        pcVar113 = pcStack_1a0;
        *puVar108 = uStack_178;
        puVar77 = puVar47;
        *(puVar47 + -8) = 0x3919;
        param_2 = sym.quotearg_style.constprop.0(pcVar113);
        *(puVar77 + -8) = 0x392f;
        uVar11 = sym.imp.dcgettext(0, "cannot open %s for reading", 5);
        puVar61 = puVar77;
        if (iStack_40 != *(in_FS_OFFSET + 0x28))
            goto code_r0x0000254a;
        uVar8 = *puVar108;
        *(puVar77 + -8) = 0x3957;
        sym.imp.error(1, uVar8, uVar11, param_2);
        puVar82 = puVar77 + 0;
    code_r0x00003957:
        *0x18260 = "%Y-%m-%d";
    } while (true);
code_r0x0000280b:
    pcVar24 = iVar107 + 1;
    goto code_r0x00002740;
code_r0x00001ee5:
    pcVar113 = *_reloc.optarg;
    *(puVar17 + -8) = 0x1ef4;
    iVar6 = sym.human_options.constprop.0(pcVar113);
    puVar61 = puVar17;
    if (iVar6 != 0)
        goto code_r0x00001efc;
    goto code_r0x00001e70;
code_r0x00001efc:
    if (iStack_40 == *(in_FS_OFFSET + 0x28))
    {
        uVar7 = uStack_110;
        pcVar113 = *_reloc.optarg;
        // WARNING: Subroutine does not return
        *(puVar17 + -8) = 0x1f2b;
        sym.xstrtol_fatal.constprop.0(iVar6, uVar7, 0x42, pcVar113);
    }
    goto code_r0x0000254a;
code_r0x00003255:
    piVar15 = &stack0xffffffffffffff18;
    if (param_1 != uVar8 && SBORROW4(param_1, uVar8) == param_1 - uVar8 < 0)
    {
        piVar15 = param_2 + uVar8;
    }
    *(puVar82 + -8) = 0x326a;
    piVar15 = sym.argv_iter_init_argv(piVar15);
    puVar61 = puVar82;
    uVar118 = *puVar108 + 1 < param_1 | uStack_140 == 2;
code_r0x00002574:
    *0x18228 = uVar118;
    if (piVar15 != NULL)
    {
        *(puVar61 + -8) = 0x2588;
        *0x18220 = sym.di_set_alloc();
        puVar59 = puVar61;
        if (*0x18220 != NULL)
        {
            if ((*0x18248 != '\0') || ((uVar118 & uVar118) == 0))
            {
                uStack_158 = uStack_158 | 0x100;
            }
            uVar118 = uStack_170;
            piVar115 = uStack_158 | uStack_140;
            pcVar113 = pcStack_1a0;
        code_r0x000025d4:
            while (*piVar15 == 0)
            {
                ppcVar16 = piVar15[5];
                if (*ppcVar16 == NULL)
                    goto code_r0x000030cd;
                piVar15[5] = ppcVar16 + 1;
                pcVar24 = *ppcVar16;
            code_r0x00002601:
                if (pcVar24 == NULL)
                {
                    // WARNING: Subroutine does not return
                    *(puVar59 + -8) = 0x452e;
                    sym.imp.__assert_fail("!\"unexpected error code from argv_iter\"", "../src/du.c", 0x438, "main");
                }
                if (pcVar113 == NULL)
                {
                    if (*pcVar24 == '\0')
                    {
                        *(puVar59 + -8) = 0x2e1e;
                        uVar11 = sym.imp.dcgettext(0, "invalid zero-length file name", 5);
                        *(puVar59 + -8) = 0x2e33;
                        sym.imp.error(0, 0, 0x12fe5, uVar11);
                        puVar59 = puVar59;
                        goto code_r0x00002de8;
                    }
                code_r0x0000263a:
                    *0x18210 = pcVar24;
                    *(puVar59 + -8) = 0x2651;
                    iStack_198 = sym.xfts_open.constprop.0(0x18210, piVar115 & 0xffffffff, 0);
                    puVar50 = puVar59;
                    uStack_1a1 = uStack_170;
                    piStack_1b8 = piVar15;
                    pcStack_1b0 = pcVar113;
                    uStack_1a8 = piVar115;
                    uStack_1a2 = uVar118;
                    while (true)
                    {
                        iVar107 = iStack_198;
                        *(puVar50 + -8) = 0x269c;
                        ppcVar16 = sym.rpl_fts_read(iVar107);
                        puVar53 = puVar50;
                        if (ppcVar16 == NULL)
                            break;
                        pcVar113 = ppcVar16[7];
                        uVar2 = *(ppcVar16 + 0xd);
                        uVar8 = uVar2;
                        uStack_140 = pcVar113;
                        if (uVar2 == 4)
                        {
                            uVar118 = 0;
                            *(puVar50 + -8) = 0x44e1;
                            uVar11 = sym.quotearg_style.constprop.0(pcVar113);
                            puVar102 = puVar50;
                            *(puVar50 + -8) = 0x44f7;
                            uVar12 = sym.imp.dcgettext(0, "cannot read directory %s", 5);
                            uVar7 = *(ppcVar16 + 8);
                            *(puVar102 + -8) = 0x450a;
                            sym.imp.error(0, uVar7, uVar12, uVar11);
                            puVar50 = puVar102;
                        code_r0x00002b20:
                            if ((*0x18238 & *0x18238) == 0)
                            {
                                ppcVar20 = ppcVar16[0x19];
                                ppcVar111 = ppcVar16[0x1a];
                            }
                            else if (*0x18238 == 2)
                            {
                                ppcVar20 = ppcVar16[0x17];
                                ppcVar111 = ppcVar16[0x18];
                            }
                            else
                            {
                                ppcVar20 = ppcVar16[0x1b];
                                ppcVar111 = ppcVar16[0x1c];
                            }
                            ppcVar27 = ppcVar111;
                            ppcVar106 = ppcVar20;
                            if (*0x1824a == '\0')
                            {
                                ppcVar110 = ppcVar16[0x16] << 9;
                            }
                            else
                            {
                                ppcVar110 = NULL;
                                if ((*(ppcVar16 + 0x11) & 0xd000) == 0x8000)
                                {
                                    ppcVar110 = ppcVar16[0x14];
                                    if (ppcVar16[0x14] < 0)
                                    {
                                        ppcVar110 = *(ppcVar16 + 0x11) & 0xd000 ^ 0x8000;
                                    }
                                }
                            }
                            ppcVar16 = ppcVar16[0xb];
                            if (*0x181d0 == NULL)
                            {
                                *0x181d0 = ppcVar16 + 10;
                                uStack_178 = ppcVar111;
                                uStack_168 = ppcVar20;
                                uStack_158 = ppcVar20;
                                ppcStack_150 = ppcVar111;
                                *(puVar50 + -8) = 0x2e86;
                                iVar107 = sym.imp.calloc(ppcVar16 + 10, 0x40);
                                puVar61 = puVar50;
                                puVar50 = puVar50;
                                if (iVar107 == 0)
                                    goto code_r0x00003bb6;
                                ppcVar27 = uStack_178;
                                ppcVar106 = uStack_168;
                                ppcVar103 = uStack_158;
                                ppcVar120 = ppcStack_150;
                                *0x181c8 = iVar107;
                            code_r0x00002c21:
                                pcVar113 = "ELF\x02\x01\x01";
                                ppcVar105 = ppcVar110;
                                ppcVar20 = ppcVar103;
                                ppcVar111 = ppcVar120;
                            }
                            else
                            {
                                ppcVar103 = ppcVar20;
                                ppcVar120 = ppcVar111;
                                if (ppcVar16 == *0x181d8)
                                    goto code_r0x00002c21;
                                if (*0x181d8 < ppcVar16)
                                {
                                    if (*0x181d0 <= ppcVar16)
                                    {
                                        uStack_158 = *0x181d8;
                                        uStack_180 = ppcVar111;
                                        uStack_178 = ppcVar20;
                                        uStack_168 = ppcVar20;
                                        ppcStack_160 = ppcVar111;
                                        *(puVar50 + -8) = 0x37dd;
                                        iVar107 = sym.imp.reallocarray(*0x181c8, ppcVar16, 0x80);
                                        puVar61 = puVar50;
                                        puVar50 = puVar50;
                                        if (iVar107 == 0)
                                            goto code_r0x00003bb6;
                                        *0x181d0 = ppcVar16 + ppcVar16;
                                        ppcVar27 = uStack_180;
                                        ppcVar106 = uStack_178;
                                        ppcVar103 = uStack_168;
                                        ppcVar120 = ppcStack_160;
                                        *0x181d8 = uStack_158;
                                        *0x181c8 = iVar107;
                                    }
                                    ppcVar20 = *0x181d8 + 1;
                                    if (ppcVar20 <= ppcVar16)
                                    {
                                        uVar11 = *0x15230;
                                        uVar12 = *0x15238;
                                        iVar107 = *0x181d8 * 0x40 + *0x181c8;
                                        do
                                        {
                                            ppcVar20 = ppcVar20 + 1;
                                            *(iVar107 + 0x40) = 0x0;
                                            *(iVar107 + 0x50) = uVar11;
                                            *(iVar107 + 0x58) = uVar12;
                                            *(iVar107 + 0x60) = 0x0;
                                            *(iVar107 + 0x70) = uVar11;
                                            *(iVar107 + 0x78) = uVar12;
                                            iVar107 = iVar107 + 0x40;
                                        } while (ppcVar20 <= ppcVar16);
                                    }
                                    goto code_r0x00002c21;
                                }
                                if (ppcVar16 != *0x181d8 + -1)
                                {
                                    // WARNING: Subroutine does not return
                                    *(puVar50 + -8) = 0x4474;
                                    sym.imp.__assert_fail("level == prev_level - 1", "../src/du.c", 0x27c, "process_file");
                                }
                                puVar18 = *0x181c8 + *0x181d8 * 0x40;
                                uVar29 = *puVar18;
                                ppcVar105 = uVar29 + ppcVar110;
                                if (CARRY8(uVar29, ppcVar110))
                                {
                                    ppcVar105 = 0xffffffffffffffff;
                                }
                                ppcVar103 = puVar18[2];
                                ppcVar120 = puVar18[3];
                                pcVar113 = puVar18[1] + 1;
                                bVar116 = ppcVar27 - ppcVar120 < 0;
                                if (-1 < ((ppcVar27 != ppcVar120 && SBORROW8(ppcVar27, ppcVar120) == bVar116) -
                                          (SBORROW8(ppcVar27, ppcVar120) != bVar116)) +
                                             ((ppcVar103 < ppcVar106) - (ppcVar106 < ppcVar103)) * 2)
                                {
                                    ppcVar103 = ppcVar20;
                                    ppcVar120 = ppcVar111;
                                }
                                if (*0x1823c == '\0')
                                {
                                    bVar116 = CARRY8(ppcVar105, puVar18[4]);
                                    ppcVar30 = ppcVar105 + puVar18[4];
                                    ppcVar105 = 0xffffffffffffffff;
                                    if (!bVar116)
                                    {
                                        ppcVar105 = ppcVar30;
                                    }
                                    ppcVar30 = puVar18[6];
                                    ppcVar121 = puVar18[7];
                                    pcVar113 = pcVar113 + puVar18[5];
                                    bVar116 = ppcVar120 - ppcVar121 < 0;
                                    if (((ppcVar120 != ppcVar121 && SBORROW8(ppcVar120, ppcVar121) == bVar116) -
                                         (SBORROW8(ppcVar120, ppcVar121) != bVar116)) +
                                            ((ppcVar30 < ppcVar103) - (ppcVar103 < ppcVar30)) * 2 <
                                        0)
                                    {
                                        ppcVar103 = puVar18[6];
                                        ppcVar120 = puVar18[7];
                                    }
                                }
                                iVar107 = (ppcVar16 << 6) + *0x181c8;
                                uVar104 = uVar29 + *(iVar107 + 0x20);
                                if (CARRY8(uVar29, *(iVar107 + 0x20)))
                                {
                                    uVar104 = 0xffffffffffffffff;
                                }
                                *(iVar107 + 0x20) = uVar104;
                                uStack_178 = puVar18[1] + *(iVar107 + 0x28);
                                uStack_168 = *(iVar107 + 0x38);
                                *(iVar107 + 0x28) = uStack_178;
                                uStack_158 = *(iVar107 + 0x30);
                                ppcVar30 = puVar18[2];
                                bVar116 = uStack_158 - ppcVar30 < 0;
                                ppcVar121 = puVar18[3];
                                bVar119 = uStack_168 - ppcVar121 < 0;
                                if ((CONCAT71(0, uStack_168 != ppcVar121 && SBORROW8(uStack_168, ppcVar121) == bVar119) - (SBORROW8(uStack_168, ppcVar121) != bVar119)) +
                                        (CONCAT31(0, uStack_158 != ppcVar30 && SBORROW8(uStack_158, ppcVar30) == bVar116) -
                                         (SBORROW8(uStack_158, ppcVar30) != bVar116)) *
                                            2 <
                                    0)
                                {
                                    uStack_158 = puVar18[2];
                                    uVar29 = puVar18[3];
                                    *(iVar107 + 0x30) = uStack_158;
                                    *(iVar107 + 0x38) = uVar29;
                                    uStack_168 = *(iVar107 + 0x38);
                                }
                                iVar9 = uVar104 + puVar18[4];
                                if (CARRY8(uVar104, puVar18[4]))
                                {
                                    iVar9 = -1;
                                }
                                *(iVar107 + 0x20) = iVar9;
                                *(iVar107 + 0x28) = uStack_178 + puVar18[5];
                                ppcVar30 = puVar18[6];
                                bVar116 = uStack_158 - ppcVar30 < 0;
                                ppcVar121 = puVar18[7];
                                bVar119 = uStack_168 - ppcVar121 < 0;
                                if (((uStack_168 != ppcVar121 && SBORROW8(uStack_168, ppcVar121) == bVar119) -
                                     (SBORROW8(uStack_168, ppcVar121) != bVar119)) +
                                        (CONCAT31(0, uStack_158 != ppcVar30 && SBORROW8(uStack_158, ppcVar30) == bVar116) -
                                         (SBORROW8(uStack_158, ppcVar30) != bVar116)) *
                                            2 <
                                    0)
                                {
                                    uVar29 = puVar18[7];
                                    *(iVar107 + 0x30) = puVar18[6];
                                    *(iVar107 + 0x38) = uVar29;
                                }
                            }
                            *0x181d8 = ppcVar16;
                            if ((*0x1823c == '\0') || ((uVar8 & 0xfffffffd) != 4))
                            {
                                puVar18 = (ppcVar16 << 6) + *0x181c8;
                                uVar29 = ppcVar110 + *puVar18;
                                if (CARRY8(ppcVar110, *puVar18))
                                {
                                    uVar29 = 0xffffffffffffffff;
                                }
                                puVar18[1] = puVar18[1] + 1;
                                *puVar18 = uVar29;
                                if ((CONCAT71(0, ppcVar27 < puVar18[3]) - (puVar18[3] < ppcVar27)) +
                                        ((ppcVar106 < puVar18[2]) - (puVar18[2] < ppcVar106)) * 2 <
                                    0)
                                {
                                    puVar18[2] = ppcVar20;
                                    puVar18[3] = ppcVar111;
                                }
                            }
                            bVar116 = CARRY8(ppcVar110, *0x181e0);
                            uVar29 = ppcVar110 + *0x181e0;
                            *0x181e0 = 0xffffffffffffffff;
                            if (!bVar116)
                            {
                                *0x181e0 = uVar29;
                            }
                            *0x181e8 = *0x181e8 + 1;
                            uVar112 = (CONCAT71(0, ppcVar27 < *0x181f8) - (*0x181f8 < ppcVar27)) +
                                      ((ppcVar106 < *0x181f0) - (*0x181f0 < ppcVar106)) * 2;
                            if ((uVar112 & uVar112) < 0)
                            {
                                *0x181f0 = ppcVar20;
                                *0x181f8 = ppcVar111;
                            }
                            if (((uVar8 & 0xfffffffd) == 4) || (*0x1824b != '\0'))
                            {
                                if (ppcVar16 <= *0x18028)
                                    goto code_r0x00002d18;
                            }
                            else if (ppcVar16 == NULL)
                            {
                            code_r0x00002d18:
                                ppcVar16 = ppcVar105;
                                if (*0x18271 != '\0')
                                {
                                    ppcVar16 = pcVar113;
                                }
                                if (*0x18240 < 0)
                                {
                                    if (ppcVar16 <= -*0x18240)
                                        goto code_r0x00002d40;
                                }
                                else if (*0x18240 <= ppcVar16)
                                {
                                code_r0x00002d40:
                                    pcVar24 = uStack_140;
                                    ppcStack_108 = ppcVar105;
                                    ppcStack_100 = pcVar113;
                                    ppcStack_f8 = ppcVar103;
                                    ppcStack_f0 = ppcVar120;
                                    *(puVar50 + -8) = 0x2d68;
                                    sym.print_size(&stack0xfffffffffffffef8, pcVar24);
                                    puVar50 = puVar50;
                                }
                            }
                        }
                        else
                        {
                            uVar118 = uStack_170;
                            if (uVar2 == 6)
                                goto code_r0x00002b20;
                            ppcVar111 = NULL;
                            ppcVar20 = **0x18250;
                            if (ppcVar20 != NULL)
                            {
                                uStack_190 = CONCAT44(uStack_190._4_4_, uVar2);
                                ppcStack_188 = ppcVar16;
                                if ((*(ppcVar20 + 1) & *(ppcVar20 + 1)) != 0)
                                    goto code_r0x0000283b;
                            code_r0x00002710:
                                if (ppcVar111 == NULL)
                                {
                                    pcVar113 = uStack_140;
                                    puVar54 = puVar53;
                                    uStack_158 = ppcVar20;
                                    *(puVar53 + -8) = 0x2a03;
                                    iVar107 = sym.imp.strlen(pcVar113);
                                    *(puVar54 + -8) = 0x2a0c;
                                    ppcVar111 = sym.imp.malloc(iVar107 + 1);
                                    puVar53 = puVar54;
                                    puVar61 = puVar54;
                                    ppcVar20 = uStack_158;
                                    if (ppcVar111 == NULL)
                                        goto code_r0x00003bb6;
                                }
                                uVar8 = *(ppcVar20 + 0xc);
                                pcVar113 = ppcVar20[2];
                                pcVar24 = uStack_140;
                                uVar112 = uVar8 & 8;
                                uStack_158 = ppcVar20;
                            code_r0x00002740:
                                puVar51 = puVar53;
                                *(puVar53 + -8) = 0x274b;
                                sym.imp.strcpy(ppcVar111, pcVar24);
                                *(puVar51 + -8) = 0x2756;
                                iVar107 = sym.hash_lookup(pcVar113, ppcVar111);
                                puVar53 = puVar51;
                                puVar52 = puVar51;
                                if (iVar107 == 0)
                                {
                                    if ((uVar112 & uVar112) != 0)
                                    {
                                        while (true)
                                        {
                                            *(puVar52 + -8) = 0x2771;
                                            puVar17 = sym.imp.strrchr(ppcVar111, 0x2f);
                                            puVar53 = puVar52;
                                            if (puVar17 == NULL)
                                                break;
                                            *puVar17 = 0;
                                            *(puVar52 + -8) = 0x2784;
                                            iVar107 = sym.hash_lookup(pcVar113, ppcVar111);
                                            puVar53 = puVar52 + 0;
                                            puVar52 = puVar52 + 0;
                                            if (iVar107 != 0)
                                                goto code_r0x00002789;
                                        }
                                    }
                                    if ((uVar8 & 0x40000000) == 0)
                                    {
                                        *(puVar53 + -8) = 0x2806;
                                        iVar107 = sym.imp.strchr(pcVar24, 0x2f);
                                        puVar53 = puVar53;
                                        if (iVar107 != 0)
                                            goto code_r0x0000280b;
                                    }
                                    ppcVar20 = uStack_158;
                                    while (ppcVar16 = *ppcVar20, ppcVar16 != NULL)
                                    {
                                        while (true)
                                        {
                                            ppcVar20 = ppcVar16;
                                            if ((*(ppcVar16 + 1) & *(ppcVar16 + 1)) == 0)
                                                goto code_r0x00002710;
                                        code_r0x0000283b:
                                            uStack_158 = ppcVar20[4];
                                            if (uStack_158 == NULL || uStack_158 < 0)
                                                break;
                                            puVar25 = ppcVar20[2] + 8;
                                            ppcVar16 = NULL;
                                            uStack_180 = ppcVar111;
                                            uStack_178 = ppcVar20;
                                            do
                                            {
                                                uVar8 = *(puVar25 + -1);
                                                uStack_168 = ppcVar16;
                                                if ((uVar8 & 0x8000000) == 0)
                                                {
                                                    uVar11 = *puVar25;
                                                    pcVar109 = sym.fnmatch_no_wildcards;
                                                    if ((uVar8 & 0x10000000) != 0)
                                                    {
                                                        pcVar109 = _reloc.fnmatch;
                                                    }
                                                    pcVar113 = uStack_140;
                                                    *(puVar53 + -8) = 0x28f2;
                                                    iVar6 = (*pcVar109)(uVar11, pcVar113, uVar8);
                                                    puVar53 = puVar53;
                                                    ppcVar16 = uStack_168;
                                                    bVar116 = iVar6 == 0;
                                                    if (((uVar8 & 0x40000000) == 0) &&
                                                        (cVar5 = *pcVar113, cVar5 != '\0'))
                                                    {
                                                        do
                                                        {
                                                            if (bVar116)
                                                                goto code_r0x00002970;
                                                            do
                                                            {
                                                                while (true)
                                                                {
                                                                    pcVar24 = pcVar113 + 1;
                                                                    pcVar113 = pcVar113 + 1;
                                                                    cVar28 = *pcVar24;
                                                                    if (cVar5 == '/')
                                                                        break;
                                                                    if (cVar28 == '\0')
                                                                        goto code_r0x00002895;
                                                                    cVar5 = *pcVar24;
                                                                }
                                                            } while (cVar28 == '/');
                                                            *(puVar53 + -8) = 0x2951;
                                                            iVar6 = (*pcVar109)(uVar11, pcVar113, uVar8);
                                                            puVar53 = puVar53;
                                                            bVar116 = iVar6 == 0;
                                                            cVar5 = *pcVar113;
                                                        } while (*pcVar113 != '\0');
                                                        ppcVar16 = uStack_168;
                                                    }
                                                    if (bVar116)
                                                    {
                                                    code_r0x00002970:
                                                        ppcVar16 = ppcStack_188;
                                                        uVar8 = uStack_190;
                                                        ppcVar20 = uStack_178;
                                                        ppcVar111 = uStack_180;
                                                        goto code_r0x0000279d;
                                                    }
                                                }
                                                else
                                                {
                                                    pcVar113 = uStack_140;
                                                    *(puVar53 + -8) = 0x288d;
                                                    iVar6 = sym.imp.regexec(puVar25, pcVar113, 0, 0);
                                                    puVar53 = puVar53;
                                                    if (iVar6 == 0)
                                                        goto code_r0x00002970;
                                                code_r0x00002895:
                                                    ppcVar16 = uStack_168;
                                                }
                                                ppcVar16 = ppcVar16 + 1;
                                                puVar25 = puVar25 + 9;
                                            } while (uStack_158 != ppcVar16);
                                            ppcVar20 = uStack_178;
                                            ppcVar111 = uStack_180;
                                            ppcVar16 = *ppcVar20;
                                            if (*ppcVar20 == NULL)
                                                goto code_r0x000029aa;
                                        }
                                    }
                                code_r0x000029aa:
                                    ppcVar16 = ppcStack_188;
                                    uVar8 = uStack_190;
                                    uVar118 = uStack_170;
                                }
                                else
                                {
                                code_r0x00002789:
                                    ppcVar16 = ppcStack_188;
                                    uVar8 = uStack_190;
                                    ppcVar20 = uStack_158;
                                code_r0x0000279d:
                                    uVar118 = 0;
                                }
                                uStack_158 = ppcVar20;
                                *(puVar53 + -8) = 0x27af;
                                sym.imp.free(ppcVar111);
                                puVar50 = puVar53;
                                if ((*(uStack_158 + 0xf) >> 5 & 1 ^ 1) == uVar118)
                                    goto code_r0x00002a24;
                                goto code_r0x000027cc;
                            }
                        code_r0x00002a24:
                            if (uVar8 == 0xb)
                            {
                                *(ppcVar16 + 0x6c) = 1;
                                iVar107 = iStack_198;
                                *(puVar50 + -8) = 13999;
                                ppcVar20 = sym.rpl_fts_read(iVar107);
                                puVar50 = puVar50;
                                if (ppcVar16 != ppcVar20)
                                {
                                    // WARNING: Subroutine does not return
                                    *(puVar50 + -8) = 0x4214;
                                    sym.imp.__assert_fail("e == ent", "../src/du.c", 0x20d, "process_file");
                                }
                                uVar8 = *(ppcVar16 + 0xd);
                            }
                            uVar118 = uVar8 == 10 | uVar8 == 0xd;
                            if (uVar118 == 0)
                            {
                                if ((((*(iStack_198 + 0x48) & 0x40) == 0) ||
                                     (ppcVar16[0xb] == NULL || ppcVar16[0xb] < 0)) ||
                                    (*(iStack_198 + 0x18) == ppcVar16[0xe]))
                                {
                                    if ((*0x18248 == '\0') &&
                                        ((*0x18228 != 0 ||
                                          (((*(ppcVar16 + 0x11) & 0xf000) != 0x4000 &&
                                            ("ELF\x02\x01\x01" < ppcVar16[0x10]))))))
                                    {
                                        pcVar113 = ppcVar16[0xe];
                                        pcVar24 = ppcVar16[0xf];
                                        uStack_158 = *0x18220;
                                        *(puVar50 + -8) = 0x2ab3;
                                        iVar107 = sym.map_device(*0x18220, pcVar113);
                                        puVar61 = puVar50;
                                        if (iVar107 == 0)
                                            goto code_r0x00003bb6;
                                        ppcVar20 = uStack_158;
                                        *(puVar50 + -8) = 0x2ace;
                                        iVar9 = sym.map_inode_number(ppcVar20, pcVar24);
                                        puVar61 = puVar50 + 0;
                                        if (iVar9 == -1)
                                            goto code_r0x00003bb6;
                                        *(puVar50 + -8) = 0x2ae5;
                                        uVar112 = sym.hash_insert_if_absent(iVar107, iVar9, 0);
                                        puVar61 = puVar50;
                                        puVar50 = puVar50;
                                        if (uVar112 == 0xffffffff)
                                            goto code_r0x00003bb6;
                                        if ((uVar112 & uVar112) == 0)
                                            goto code_r0x000027cc;
                                    }
                                    if (uVar8 != 2)
                                    {
                                        if (uVar8 == 7)
                                        {
                                            pcVar113 = uStack_140;
                                            *(puVar50 + -8) = 0x4480;
                                            uVar11 = sym.quotearg_n_style_colon.constprop.0(pcVar113);
                                            uVar7 = *(ppcVar16 + 8);
                                            *(puVar50 + -8) = 0x4497;
                                            sym.imp.error(0, uVar7, 0x12fe5, uVar11);
                                            puVar50 = puVar50;
                                        }
                                        else
                                        {
                                            if (uVar8 == 1)
                                                goto code_r0x000027d5;
                                            uVar118 = uStack_170;
                                        }
                                        goto code_r0x00002b20;
                                    }
                                    uStack_158 = CONCAT44(uStack_158._4_4_, *(iStack_198 + 0x48));
                                    uVar8 = *(iStack_198 + 0x48) & 0x11;
                                    if ((uVar8 != 0x10) && ((uVar8 != 0x11 || (ppcVar16[0xb] == NULL))))
                                        goto code_r0x000027d5;
                                    ppcVar111 = *0x18200;
                                    ppcVar20 = *ppcVar16;
                                    if (*0x18200 == NULL)
                                    {
                                        *(puVar50 + -8) = 0x32cf;
                                        *0x18200 = sym.di_set_alloc();
                                        puVar61 = puVar50;
                                        if (*0x18200 == NULL)
                                            goto code_r0x00003bb6;
                                        *(puVar50 + -8) = 0x32f2;
                                        uStack_168 = sym.rpl_fopen.constprop.0("/proc/self/mountinfo", "re");
                                        if (uStack_168 == NULL)
                                        {
                                            *(puVar50 + -8) = 0x3d60;
                                            iVar107 = sym.imp.setmntent("/etc/mtab");
                                            puVar50 = puVar50;
                                            puVar90 = puVar50;
                                            if (iVar107 != 0)
                                            {
                                                uStack_158 = &stack0xfffffffffffffee0;
                                                uStack_180 = NULL;
                                                uStack_178 = ppcVar20;
                                                uStack_168 = ppcVar16;
                                                while (true)
                                                {
                                                    *(puVar90 + -8) = 0x3dd0;
                                                    puVar25 = sym.imp.getmntent(iVar107);
                                                    if (puVar25 == NULL)
                                                        break;
                                                    *(puVar90 + -8) = 0x3deb;
                                                    iVar9 = sym.imp.hasmntopt(puVar25, "bind");
                                                    *(puVar90 + -8) = 0x3df8;
                                                    ppcVar16 = sym.imp.malloc(0x38);
                                                    puVar61 = puVar90 + 0;
                                                    if (ppcVar16 == NULL)
                                                        goto code_r0x00003bb6;
                                                    uVar11 = *puVar25;
                                                    uVar118 = 1;
                                                    iVar1 = -8;
                                                    *(puVar90 + iVar1) = 0x3e12;
                                                    pcVar113 = sym.xstrdup(uVar11);
                                                    *ppcVar16 = pcVar113;
                                                    uVar11 = puVar25[1];
                                                    puVar86 = puVar90 + 0;
                                                    *(puVar90 + iVar1) = 0x3e1f;
                                                    pcVar113 = sym.xstrdup(uVar11);
                                                    ppcVar16[2] = NULL;
                                                    ppcVar16[1] = pcVar113;
                                                    uVar11 = puVar25[2];
                                                    puVar87 = puVar86;
                                                    *(puVar86 + -8) = 0x3e35;
                                                    pcVar113 = sym.xstrdup(uVar11);
                                                    *(ppcVar16 + 5) = *(ppcVar16 + 5) | 4;
                                                    ppcVar16[3] = pcVar113;
                                                    *(puVar87 + -8) = 0x3e52;
                                                    iVar6 = sym.imp.strcmp(pcVar113, "autofs");
                                                    puVar88 = puVar87;
                                                    if (iVar6 != 0)
                                                    {
                                                        *(puVar87 + -8) = 0x3e69;
                                                        iVar6 = sym.imp.strcmp(pcVar113, "proc");
                                                        puVar88 = puVar86 + 0;
                                                        if (iVar6 != 0)
                                                        {
                                                            *(puVar86 + -8) = 16000;
                                                            iVar6 = sym.imp.strcmp(pcVar113, "subfs");
                                                            puVar88 = puVar90 + 0 + 0;
                                                            if (iVar6 != 0)
                                                            {
                                                                *(puVar90 + iVar1 + 8 + -8) = 0x3e97;
                                                                iVar6 = sym.imp.strcmp(pcVar113, "debugfs");
                                                                puVar88 = puVar90 + 0 + -8 + 8;
                                                                if (iVar6 != 0)
                                                                {
                                                                    *(puVar90 + iVar1 + 8 + -8) = 0x3eae;
                                                                    iVar6 = sym.imp.strcmp(pcVar113, "devpts");
                                                                    puVar88 = puVar90 + 0;
                                                                    if (iVar6 != 0)
                                                                    {
                                                                        *(puVar90 + 0 + -8) = 0x3ec5;
                                                                        iVar6 = sym.imp.strcmp(pcVar113, "fusectl");
                                                                        puVar88 = puVar90 + 0 + 0;
                                                                        if (iVar6 != 0)
                                                                        {
                                                                            *(puVar90 + 0 + -8) = 0x3edc;
                                                                            iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                   "fuse.portal");
                                                                            puVar88 = puVar90 + 0;
                                                                            if (iVar6 != 0)
                                                                            {
                                                                                *(puVar90 + 0 + -8) = 0x3ef3;
                                                                                iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                       "mqueue");
                                                                                puVar88 = puVar90 + 0 + 0;
                                                                                if (iVar6 != 0)
                                                                                {
                                                                                    *(puVar90 + 0 + -8) = 0x3f0a;
                                                                                    iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                           "rpc_pipefs");
                                                                                    puVar88 = puVar90 + 0;
                                                                                    if (iVar6 != 0)
                                                                                    {
                                                                                        *(puVar90 + 0 + -8) = 0x3f1d;
                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "sysfs");
                                                                                        puVar88 = puVar90 + 0 + 0;
                                                                                        if (iVar6 != 0)
                                                                                        {
                                                                                            *(puVar90 + 0 + -8) = 0x3f30;
                                                                                            iVar6 = sym.imp.strcmp(pcVar113, "devfs");
                                                                                            puVar88 = puVar90 + 0;
                                                                                            if (iVar6 != 0)
                                                                                            {
                                                                                                *(puVar90 + 0 + -8) = 0x3f43;
                                                                                                iVar6 = sym.imp.strcmp(pcVar113, "kernfs");
                                                                                                puVar88 = puVar90 + 0 + 0;
                                                                                                if (iVar6 != 0)
                                                                                                {
                                                                                                    *(puVar90 + 0 + -8) = 0x3f56;
                                                                                                    iVar6 = sym.imp.strcmp(pcVar113, "ignore");
                                                                                                    puVar88 = puVar90 + 0;
                                                                                                    if (iVar6 != 0)
                                                                                                    {
                                                                                                        *(puVar90 + 0 + -8) = 0x3f69;
                                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "none");
                                                                                                        puVar88 = puVar90 + 0 + 0;
                                                                                                        uVar118 = iVar9 == 0 & iVar6 == 0;
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    bVar116 = true;
                                                    pcVar24 = *ppcVar16;
                                                    *(ppcVar16 + 5) = *(ppcVar16 + 5) & 0xfe | uVar118;
                                                    *(puVar88 + -8) = 0x3fa3;
                                                    iVar9 = sym.imp.strchr(pcVar24);
                                                    puVar90 = puVar88;
                                                    puVar89 = puVar88;
                                                    if (iVar9 == 0)
                                                    {
                                                        if ((*pcVar24 != '/') || (pcVar24[1] != '/'))
                                                        {
                                                        code_r0x00003fb6:
                                                            bVar116 = true;
                                                            *(puVar89 + -8) = 0x3fcb;
                                                            iVar6 = sym.imp.strcmp(pcVar113);
                                                            puVar90 = puVar89;
                                                            if (iVar6 != 0)
                                                            {
                                                                *(puVar89 + -8) = 0x3fe2;
                                                                iVar6 = sym.imp.strcmp(pcVar113);
                                                                puVar90 = puVar89 + 0;
                                                                if (iVar6 != 0)
                                                                {
                                                                    *(puVar89 + -8) = 0x3ff9;
                                                                    iVar6 = sym.imp.strcmp(pcVar113);
                                                                    puVar90 = puVar89;
                                                                    if (iVar6 != 0)
                                                                    {
                                                                        *(puVar89 + -8) = 0x4010;
                                                                        iVar6 = sym.imp.strcmp(pcVar113);
                                                                        puVar90 = puVar89 + 0;
                                                                        if (iVar6 != 0)
                                                                        {
                                                                            *(puVar89 + -8) = 0x4027;
                                                                            iVar6 = sym.imp.strcmp(pcVar113);
                                                                            puVar90 = puVar89;
                                                                            if (iVar6 != 0)
                                                                            {
                                                                                *(puVar89 + -8) = 0x403e;
                                                                                iVar6 = sym.imp.strcmp(pcVar113);
                                                                                puVar90 = puVar89 + 0;
                                                                                if (iVar6 != 0)
                                                                                {
                                                                                    *(puVar89 + -8) = 0x4055;
                                                                                    iVar6 = sym.imp.strcmp(pcVar113);
                                                                                    puVar90 = puVar89;
                                                                                    if (iVar6 != 0)
                                                                                    {
                                                                                        *(puVar89 + -8) = 0x406c;
                                                                                        iVar6 = sym.imp.strcmp(pcVar113);
                                                                                        puVar90 = puVar89 + 0;
                                                                                        if (iVar6 != 0)
                                                                                        {
                                                                                            *(puVar89 + -8) = 0x4083;
                                                                                            iVar6 = sym.imp.strcmp(
                                                                                                pcVar113);
                                                                                            puVar90 = puVar89;
                                                                                            if (iVar6 != 0)
                                                                                            {
                                                                                                *(puVar89 + -8) = 0x409d;
                                                                                                iVar6 = sym.imp.strcmp("-hosts");
                                                                                                puVar90 = puVar89 + 0;
                                                                                                bVar116 = iVar6 == 0;
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        else
                                                        {
                                                            *(puVar88 + -8) = 0x42b2;
                                                            iVar6 = sym.imp.strcmp(pcVar113);
                                                            puVar90 = puVar88 + 0;
                                                            if (iVar6 != 0)
                                                            {
                                                                *(puVar88 + -8) = 0x42c9;
                                                                iVar6 = sym.imp.strcmp(pcVar113);
                                                                puVar90 = puVar88;
                                                                if (iVar6 != 0)
                                                                {
                                                                    *(puVar88 + -8) = 0x42e0;
                                                                    iVar6 = sym.imp.strcmp(pcVar113);
                                                                    puVar90 = puVar88 + 0;
                                                                    puVar89 = puVar88 + 0;
                                                                    if (iVar6 != 0)
                                                                        goto code_r0x00003fb6;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    ppcVar16[4] = 0xffffffffffffffff;
                                                    *(ppcVar16 + 5) = *(ppcVar16 + 5) & 0xfd | bVar116 + bVar116;
                                                    *uStack_158 = ppcVar16;
                                                    uStack_158 = ppcVar16 + 6;
                                                }
                                                ppcVar16 = uStack_168;
                                                ppcVar111 = uStack_180;
                                                ppcVar20 = uStack_178;
                                                *(puVar90 + -8) = 0x40c8;
                                                iVar6 = sym.imp.endmntent();
                                                puVar93 = puVar90;
                                                puVar50 = puVar90;
                                                if (iVar6 != 0)
                                                    goto code_r0x00003ae6;
                                                goto code_r0x000040d0;
                                            }
                                        }
                                        else
                                        {
                                            uStack_158 = &stack0xfffffffffffffee0;
                                            uStack_178 = &stack0xfffffffffffffee8;
                                            uStack_180 = &stack0xfffffffffffffed4;
                                            ppcStack_188 = &stack0xfffffffffffffed0;
                                            pcStack_118 = NULL;
                                            uStack_110 = 0;
                                            ppcStack_1c8 = NULL;
                                            puVar17 = puVar50 + 0;
                                            ppcStack_1c0 = ppcVar20;
                                            uStack_190 = ppcVar16;
                                            while (true)
                                            {
                                                puVar62 = puVar17;
                                                ppcVar16 = uStack_178;
                                                puVar17 = puStack_148;
                                                *(puVar62 + -8) = 0x337f;
                                                iVar107 = sym.imp.__getdelim(ppcVar16, puVar17, 10);
                                                pcVar113 = pcStack_118;
                                                if (iVar107 == -1)
                                                    break;
                                                ppcVar16 = ppcStack_188;
                                                *(puVar62 + -8) = 0x33b3;
                                                iVar6 = sym.imp.__isoc23_sscanf(pcVar113, "%*u %*u %u:%u %n",
                                                                                &stack0xfffffffffffffecc, ppcVar16);
                                                puVar17 = puVar62 + 0;
                                                if (iVar6 + -2 < 2)
                                                {
                                                    pcVar113 = pcStack_118 + iStack_12c;
                                                    *(puVar62 + -8) = 0x33d6;
                                                    puVar21 = sym.imp.strchr(pcVar113, 0x20);
                                                    puVar17 = puVar62;
                                                    if (puVar21 != NULL)
                                                    {
                                                        *puVar21 = 0;
                                                        puVar21 = puVar21 + 1;
                                                        *(puVar62 + -8) = 0x33ef;
                                                        puVar22 = sym.imp.strchr(puVar21, 0x20);
                                                        puVar17 = puVar62 + 0;
                                                        if (puVar22 != NULL)
                                                        {
                                                            *puVar22 = 0;
                                                            *(puVar62 + -8) = 0x340b;
                                                            iVar107 = sym.imp.strstr(puVar22 + 1, 0x13208);
                                                            puVar17 = puVar62;
                                                            if (iVar107 != 0)
                                                            {
                                                                iVar107 = iVar107 + 3;
                                                                *(puVar62 + -8) = 0x3425;
                                                                puVar22 = sym.imp.strchr(iVar107, 0x20);
                                                                puVar17 = puVar62 + 0;
                                                                if (puVar22 != NULL)
                                                                {
                                                                    *puVar22 = 0;
                                                                    puVar22 = puVar22 + 1;
                                                                    *(puVar62 + -8) = 0x3442;
                                                                    puVar23 = sym.imp.strchr(puVar22, 0x20);
                                                                    puVar17 = puVar62;
                                                                    if (puVar23 != NULL)
                                                                    {
                                                                        *puVar23 = 0;
                                                                        *(puVar62 + -8) = 0x3456;
                                                                        sym.unescape_tab(puVar22);
                                                                        puVar63 = puVar62 + 0;
                                                                        *(puVar62 + -8) = 0x345e;
                                                                        sym.unescape_tab(puVar21);
                                                                        puVar64 = puVar63;
                                                                        *(puVar63 + -8) = 0x3466;
                                                                        sym.unescape_tab(pcVar113);
                                                                        puVar65 = puVar64;
                                                                        *(puVar64 + -8) = 0x346e;
                                                                        sym.unescape_tab(iVar107);
                                                                        *(puVar65 + -8) = 0x3478;
                                                                        ppcVar16 = sym.imp.malloc(0x38);
                                                                        puVar61 = puVar65;
                                                                        if (ppcVar16 == NULL)
                                                                            goto code_r0x00003bb6;
                                                                        bVar116 = true;
                                                                        iVar9 = -8;
                                                                        *(puVar65 + iVar9) = 0x3492;
                                                                        pcVar24 = sym.xstrdup(puVar22);
                                                                        puVar66 = puVar63 + 0;
                                                                        *ppcVar16 = pcVar24;
                                                                        puVar67 = puVar66;
                                                                        *(puVar64 + iVar9) = 0x349e;
                                                                        pcVar24 = sym.xstrdup(puVar21);
                                                                        ppcVar16[1] = pcVar24;
                                                                        puVar68 = puVar67;
                                                                        *(puVar67 + -8) = 0x34ab;
                                                                        pcVar113 = sym.xstrdup(pcVar113);
                                                                        ppcVar16[2] = pcVar113;
                                                                        puVar69 = puVar68;
                                                                        *(puVar68 + -8) = 0x34b8;
                                                                        pcVar113 = sym.xstrdup(iVar107);
                                                                        *(ppcVar16 + 5) = *(ppcVar16 + 5) | 4;
                                                                        ppcVar16[3] = pcVar113;
                                                                        ppcVar16[4] = uStack_130 << 0xc &
                                                                                          0xffffffL << 0x14 |
                                                                                      uStack_134 << 0x20 &
                                                                                          0xfffffL << 0x2c |
                                                                                      uStack_134 << 8 & 0xfff00 |
                                                                                      uStack_130;
                                                                        *(puVar69 + -8) = 0x351f;
                                                                        iVar6 = sym.imp.strcmp(pcVar113, "autofs");
                                                                        puVar70 = puVar69;
                                                                        if (iVar6 != 0)
                                                                        {
                                                                            iVar107 = -8;
                                                                            *(puVar69 + iVar107) = 0x3536;
                                                                            iVar6 = sym.imp.strcmp(pcVar113, "proc");
                                                                            puVar70 = puVar68 + 0;
                                                                            if (iVar6 != 0)
                                                                            {
                                                                                *(puVar68 + iVar107) = 0x354d;
                                                                                iVar6 = sym.imp.strcmp(pcVar113, "subfs");
                                                                                puVar70 = puVar67 + 0;
                                                                                if (iVar6 != 0)
                                                                                {
                                                                                    *(puVar66 + 0 + -8) = 0x3564;
                                                                                    iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                           "debugfs");
                                                                                    puVar70 = puVar66 + iVar107 + 8;
                                                                                    if (iVar6 != 0)
                                                                                    {
                                                                                        *(puVar66 + 0 + -8) = 0x357b;
                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "devpts");
                                                                                        puVar70 = puVar63 + iVar9 + 8;
                                                                                        if (iVar6 != 0)
                                                                                        {
                                                                                            *(puVar63 + iVar9 + 8 + -8) = 0x3592;
                                                                                            iVar6 = sym.imp.strcmp(pcVar113, "fusectl");
                                                                                            puVar70 = puVar63 + iVar9 + 8 + 0;
                                                                                            if (iVar6 != 0)
                                                                                            {
                                                                                                *(puVar63 + iVar9 + 8 + -8) = 0x35a9;
                                                                                                iVar6 = sym.imp.strcmp(pcVar113, "fuse.portal");
                                                                                                puVar70 = puVar63 + iVar9 + 8;
                                                                                                if (iVar6 != 0)
                                                                                                {
                                                                                                    *(puVar63 + iVar9 + 8 + -8) = 0x35c0;
                                                                                                    iVar6 = sym.imp.strcmp(pcVar113, "mqueue");
                                                                                                    puVar70 = puVar63 + iVar9 + 8 + 0;
                                                                                                    if (iVar6 != 0)
                                                                                                    {
                                                                                                        *(puVar63 + iVar9 + 8 + -8) = 0x35d3;
                                                                                                        iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                                               "rpc_pipefs");
                                                                                                        puVar70 = puVar63 + iVar9 + 8;
                                                                                                        if (iVar6 != 0)
                                                                                                        {
                                                                                                            *(puVar63 + iVar9 + 8 + -8) = 0x35e6;
                                                                                                            iVar6 = sym.imp.strcmp(pcVar113, "sysfs");
                                                                                                            puVar70 = puVar63 + iVar9 + 8 + 0;
                                                                                                            if (iVar6 != 0)
                                                                                                            {
                                                                                                                *(puVar63 + iVar9 + 8 + -8) = 0x35f9;
                                                                                                                iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                                                       "devfs");
                                                                                                                puVar70 = puVar63 + iVar9 + 8;
                                                                                                                if (iVar6 != 0)
                                                                                                                {
                                                                                                                    *(puVar63 + iVar9 + 8 + -8) =
                                                                                                                        0x360c;
                                                                                                                    iVar6 = sym.imp.strcmp(pcVar113, "kernfs");
                                                                                                                    puVar70 = puVar63 + iVar9 + 8 + 0;
                                                                                                                    if (iVar6 != 0)
                                                                                                                    {
                                                                                                                        *(puVar63 + iVar9 + 8 + -8) = 0x361f;
                                                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "ignore");
                                                                                                                        puVar70 = puVar63 + iVar9 + 8;
                                                                                                                        if (iVar6 != 0)
                                                                                                                        {
                                                                                                                            *(puVar63 + iVar9 + 8 + -8) = 0x3635;
                                                                                                                            iVar6 = sym.imp.strcmp(pcVar113, "none");
                                                                                                                            puVar70 = puVar63 + iVar9 + 8 + 0;
                                                                                                                            bVar116 = iVar6 == 0;
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        bVar119 = true;
                                                                        pcVar24 = *ppcVar16;
                                                                        *(ppcVar16 + 5) = *(ppcVar16 + 5) & 0xfe | bVar116;
                                                                        *(puVar70 + -8) = 0x3663;
                                                                        iVar107 = sym.imp.strchr(pcVar24, 0x3a);
                                                                        puVar85 = puVar70;
                                                                        puVar84 = puVar70;
                                                                        if (iVar107 == 0)
                                                                        {
                                                                            if ((*pcVar24 != '/') || (pcVar24[1] != '/'))
                                                                            {
                                                                            code_r0x00003c5b:
                                                                                bVar119 = true;
                                                                                *(puVar84 + -8) = 0x3c70;
                                                                                iVar6 = sym.imp.strcmp(pcVar113, "acfs");
                                                                                puVar85 = puVar84;
                                                                                if (iVar6 != 0)
                                                                                {
                                                                                    *(puVar84 + -8) = 0x3c87;
                                                                                    iVar6 = sym.imp.strcmp(pcVar113, 0x13287);
                                                                                    puVar85 = puVar84 + 0;
                                                                                    if (iVar6 != 0)
                                                                                    {
                                                                                        *(puVar84 + -8) = 0x3c9e;
                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "coda");
                                                                                        puVar85 = puVar84;
                                                                                        if (iVar6 != 0)
                                                                                        {
                                                                                            *(puVar84 + -8) = 0x3cb5;
                                                                                            iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                                   "auristorfs");
                                                                                            puVar85 = puVar84 + 0;
                                                                                            if (iVar6 != 0)
                                                                                            {
                                                                                                *(puVar84 + -8) = 0x3ccc;
                                                                                                iVar6 = sym.imp.strcmp(pcVar113,
                                                                                                                       "fhgfs");
                                                                                                puVar85 = puVar84;
                                                                                                if (iVar6 != 0)
                                                                                                {
                                                                                                    *(puVar84 + -8) = 0x3ce3;
                                                                                                    iVar6 = sym.imp.strcmp(pcVar113, "gpfs");
                                                                                                    puVar85 = puVar84 + 0;
                                                                                                    if (iVar6 != 0)
                                                                                                    {
                                                                                                        *(puVar84 + -8) = 0x3cfa;
                                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "ibrix");
                                                                                                        puVar85 = puVar84;
                                                                                                        if (iVar6 != 0)
                                                                                                        {
                                                                                                            *(puVar84 + -8) = 0x3d11;
                                                                                                            iVar6 = sym.imp.strcmp(pcVar113, "ocfs2");
                                                                                                            puVar85 = puVar84 + 0;
                                                                                                            if (iVar6 != 0)
                                                                                                            {
                                                                                                                *(puVar84 + -8) = 0x3d28;
                                                                                                                iVar6 = sym.imp.strcmp(pcVar113, "vxfs");
                                                                                                                puVar85 = puVar84;
                                                                                                                if (iVar6 != 0)
                                                                                                                {
                                                                                                                    *(puVar84 + -8) = 0x3d42;
                                                                                                                    iVar6 = sym.imp.strcmp("-hosts", pcVar24);
                                                                                                                    puVar85 = puVar84 + 0;
                                                                                                                    bVar119 = iVar6 == 0;
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            else
                                                                            {
                                                                                *(puVar70 + -8) = 0x419c;
                                                                                iVar6 = sym.imp.strcmp(pcVar113, "smbfs");
                                                                                puVar85 = puVar70 + 0;
                                                                                if (iVar6 != 0)
                                                                                {
                                                                                    *(puVar70 + -8) = 0x41b3;
                                                                                    iVar6 = sym.imp.strcmp(pcVar113, "smb3");
                                                                                    puVar85 = puVar70;
                                                                                    if (iVar6 != 0)
                                                                                    {
                                                                                        *(puVar70 + -8) = 0x41ca;
                                                                                        iVar6 = sym.imp.strcmp(pcVar113, "cifs");
                                                                                        puVar85 = puVar70 + 0;
                                                                                        puVar84 = puVar70 + 0;
                                                                                        if (iVar6 != 0)
                                                                                            goto code_r0x00003c5b;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        *(ppcVar16 + 5) = *(ppcVar16 + 5) & 0xfd | bVar119 * '\x02';
                                                                        *uStack_158 = ppcVar16;
                                                                        uStack_158 = ppcVar16 + 6;
                                                                        puVar17 = puVar85;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            ppcVar16 = uStack_190;
                                            ppcVar20 = ppcStack_1c0;
                                            ppcVar111 = ppcStack_1c8;
                                            *(puVar62 + -8) = 0x3ac1;
                                            sym.imp.free(pcVar113);
                                            if ((*uStack_168 & 0x20) == 0)
                                            {
                                                *(puVar62 + -8) = 0x3add;
                                                iVar6 = sym.rpl_fclose();
                                                puVar50 = puVar62 + 0;
                                                puVar93 = puVar62 + 0;
                                                if (iVar6 != -1)
                                                {
                                                code_r0x00003ae6:
                                                    *uStack_158 = NULL;
                                                    ppcVar111 = ppcStack_120;
                                                    goto code_r0x00003af9;
                                                }
                                            }
                                            else
                                            {
                                                *(puVar62 + -8) = 0x415e;
                                                puVar26 = sym.imp.__errno_location();
                                                ppcVar106 = uStack_168;
                                                uStack_178 = CONCAT44(uStack_178._4_4_, *puVar26);
                                                *(puVar62 + -8) = 0x4175;
                                                sym.rpl_fclose(ppcVar106);
                                                puVar93 = puVar62;
                                                *puVar26 = uStack_178;
                                            }
                                        code_r0x000040d0:
                                            *(puVar93 + -8) = 0x40d5;
                                            uStack_168 = sym.imp.__errno_location();
                                            puVar50 = puVar93;
                                            uVar7 = *uStack_168;
                                            *uStack_158 = NULL;
                                            while (ppcVar106 = ppcStack_120, ppcVar106 != NULL)
                                            {
                                                uStack_158 = ppcStack_120[6];
                                                pcVar113 = *ppcVar106;
                                                *(puVar50 + -8) = 0x4127;
                                                sym.imp.free(pcVar113);
                                                pcVar113 = ppcVar106[1];
                                                puVar91 = puVar50;
                                                *(puVar50 + -8) = 0x4130;
                                                sym.imp.free(pcVar113);
                                                pcVar113 = ppcVar106[2];
                                                *(puVar91 + -8) = 0x4139;
                                                sym.imp.free(pcVar113);
                                                puVar92 = puVar91;
                                                if ((*(ppcVar106 + 5) & 4) != 0)
                                                {
                                                    pcVar113 = ppcVar106[3];
                                                    *(puVar91 + -8) = 0x4148;
                                                    sym.imp.free(pcVar113);
                                                    puVar92 = puVar91 + 0;
                                                }
                                                *(puVar92 + -8) = 0x40fa;
                                                sym.imp.free(ppcVar106);
                                                puVar50 = puVar92;
                                                ppcStack_120 = uStack_158;
                                            }
                                            *uStack_168 = uVar7;
                                        }
                                    code_r0x00003af9:
                                        uStack_158 = &stack0xffffffffffffff28;
                                        while (ppcVar111 != NULL)
                                        {
                                            if ((*(ppcVar111 + 5) & 3) == 0)
                                            {
                                                pcVar113 = ppcVar111[1];
                                                ppcVar106 = uStack_158;
                                                *(puVar50 + -8) = 0x3b5e;
                                                iVar6 = sym.imp.stat(pcVar113, ppcVar106);
                                                if (iVar6 == 0)
                                                {
                                                    pcVar113 = apcStack_d8[0];
                                                    uVar11 = apcStack_d8[1];
                                                    uStack_168 = *0x18200;
                                                    *(puVar50 + -8) = 0x3b83;
                                                    iVar107 = sym.map_device(*0x18200, pcVar113);
                                                    puVar61 = puVar50 + 0;
                                                    if (iVar107 == 0)
                                                        goto code_r0x00003bb6;
                                                    ppcVar106 = uStack_168;
                                                    *(puVar50 + -8) = 0x3b9a;
                                                    iVar9 = sym.map_inode_number(ppcVar106, uVar11);
                                                    puVar61 = puVar50;
                                                    if (iVar9 == -1)
                                                        goto code_r0x00003bb6;
                                                    *(puVar50 + -8) = 0x3bad;
                                                    iVar6 = sym.hash_insert_if_absent(iVar107, iVar9, 0);
                                                    puVar61 = puVar50 + 0;
                                                    puVar50 = puVar50 + 0;
                                                    if (iVar6 == -1)
                                                        goto code_r0x00003bb6;
                                                }
                                            }
                                            pcVar113 = *ppcVar111;
                                            ppcVar106 = ppcVar111[6];
                                            *(puVar50 + -8) = 0x3b16;
                                            sym.imp.free(pcVar113);
                                            pcVar113 = ppcVar111[1];
                                            puVar80 = puVar50;
                                            *(puVar50 + -8) = 0x3b1f;
                                            sym.imp.free(pcVar113);
                                            pcVar113 = ppcVar111[2];
                                            *(puVar80 + -8) = 0x3b28;
                                            sym.imp.free(pcVar113);
                                            puVar81 = puVar80;
                                            if ((*(ppcVar111 + 5) & 4) != 0)
                                            {
                                                pcVar113 = ppcVar111[3];
                                                *(puVar80 + -8) = 0x3bd7;
                                                sym.imp.free(pcVar113);
                                                puVar81 = puVar80 + 0;
                                            }
                                            *(puVar81 + -8) = 0x3b3e;
                                            sym.imp.free(ppcVar111);
                                            puVar50 = puVar81;
                                            ppcVar111 = ppcVar106;
                                        }
                                    }
                                    for (; (ppcVar16 != NULL && (ppcVar20 != ppcVar16)); ppcVar16 = ppcVar16[1])
                                    {
                                        ppcVar111 = *0x18200;
                                        pcVar113 = ppcVar16[0xe];
                                        pcVar24 = ppcVar16[0xf];
                                        *(puVar50 + -8) = 0x3836;
                                        iVar107 = sym.map_device(ppcVar111, pcVar113);
                                        if (iVar107 != 0)
                                        {
                                            puVar72 = puVar50;
                                            puVar73 = puVar50;
                                            puVar71 = puVar50 + -8;
                                            *(puVar50 + -8) = 0x3849;
                                            iVar9 = sym.map_inode_number(ppcVar111, pcVar24);
                                            puVar50 = puVar50 + 0;
                                            if (iVar9 != -1)
                                            {
                                                *puVar71 = 0x385a;
                                                iVar107 = sym.hash_lookup(iVar107, iVar9);
                                                puVar50 = puVar73;
                                                if (iVar107 != 0)
                                                    goto code_r0x000027d5;
                                            }
                                        }
                                    }
                                    pcVar113 = uStack_140;
                                    *(puVar50 + -8) = 0x3878;
                                    sym.quotearg_n_style_colon.constprop.0(pcVar113);
                                    puVar74 = puVar50;
                                    *(puVar50 + -8) = 0x388e;
                                    uVar11 = sym.imp.dcgettext(0,
                                                               "WARNING: Circular directory structure.\nThis almost certainly means that you have a corrupted file system.\nNOTIFY YOUR SYSTEM MANAGER.\nThe following directory is part of the cycle:\n  %s\n", 5);
                                    *(puVar74 + -8) = 0x389f;
                                    sym.imp.error(0, 0, uVar11);
                                    puVar50 = puVar74;
                                    goto code_r0x0000389f;
                                }
                            code_r0x000027cc:
                                if (uVar8 + -1 == 0)
                                {
                                    *(ppcVar16 + 0x6c) = 4;
                                    iVar107 = iStack_198;
                                    *(puVar50 + -8) = 0x3162;
                                    ppcVar20 = sym.rpl_fts_read(iVar107);
                                    if (ppcVar16 != ppcVar20)
                                    {
                                        // WARNING: Subroutine does not return
                                        *(puVar50 + -8) = 0x318a;
                                        sym.imp.__assert_fail("e == ent", "../src/du.c", 0x22e, "process_file");
                                    }
                                }
                            code_r0x000027d5:
                                uVar118 = uStack_170;
                            }
                            else
                            {
                                pcVar113 = uStack_140;
                                *(puVar50 + -8) = 0x44a8;
                                sym.quotearg_style.constprop.0(pcVar113);
                                puVar101 = puVar50;
                                *(puVar50 + -8) = 0x44be;
                                uVar11 = sym.imp.dcgettext(0, "cannot access %s", 5);
                                uVar7 = *(ppcVar16 + 8);
                                *(puVar101 + -8) = 0x44d1;
                                sym.imp.error(0, uVar7, uVar11);
                                puVar50 = puVar101;
                            code_r0x0000389f:
                                uVar118 = 0;
                            }
                        }
                        uStack_1a1 = uStack_1a1 & uVar118;
                    }
                    *(puVar50 + -8) = 0x3066;
                    piVar19 = sym.imp.__errno_location();
                    puVar100 = puVar50;
                    uVar118 = uStack_1a2;
                    pcVar113 = pcStack_1b0;
                    piVar15 = piStack_1b8;
                    piVar115 = uStack_1a8;
                    if (*piVar19 != 0)
                    {
                        uVar11 = *(iStack_198 + 0x20);
                        *(puVar50 + -8) = 0x441a;
                        uStack_140 = sym.quotearg_n_style_colon.constprop.0(uVar11);
                        *(puVar50 + -8) = 0x4434;
                        uVar11 = sym.imp.dcgettext(0, "fts_read failed: %s", 5);
                        pcVar24 = uStack_140;
                        iVar6 = *piVar19;
                        *(puVar50 + 0 + -8) = 0x4449;
                        sym.imp.error(0, iVar6, uVar11, pcVar24);
                        puVar100 = puVar50 + 0;
                        uStack_1a1 = 0;
                    }
                    *0x181d8 = NULL;
                    *(puVar100 + -8) = 0x30a5;
                    iVar6 = sym.rpl_fts_close();
                    puVar59 = puVar100;
                    puVar99 = puVar100;
                    if (iVar6 != 0)
                        goto code_r0x000043ae;
                    goto code_r0x000030ad;
                }
                if ((((*pcVar113 != '-') || (pcVar113[1] != '\0')) || (*pcVar24 != '-')) || (pcVar24[1] != '\0'))
                {
                    if (*pcVar24 != '\0')
                        goto code_r0x0000263a;
                }
                else
                {
                    *(puVar59 + -8) = 0x2d75;
                    uVar11 = sym.quotearg_style.constprop.0();
                    puVar55 = puVar59;
                    *(puVar59 + -8) = 0x2d8b;
                    uVar12 = sym.imp.dcgettext(0, "when reading file names from stdin, no file name of %s allowed", 5);
                    *(puVar55 + -8) = 0x2d9c;
                    sym.imp.error(0, 0, uVar12, uVar11);
                    puVar59 = puVar55;
                    if (*pcVar24 != '\0')
                        goto code_r0x00002de8;
                }
                *(puVar59 + -8) = 0x2dc2;
                sym.imp.dcgettext(0, "invalid zero-length file name", 5);
                puVar56 = puVar59;
                *(puVar59 + -8) = 0x2dcd;
                uVar11 = sym.quotearg_n_style_colon.constprop.0();
                *(puVar56 + -8) = 0x2de8;
                sym.imp.error(0, 0, "%s:%td: %s", uVar11);
                puVar59 = puVar56;
            code_r0x00002de8:
                uVar118 = 0;
            }
            *(puVar59 + -8) = 0x25ef;
            iVar107 = sym.imp.getdelim(piVar15 + 2, piVar15 + 3, 0);
            puVar59 = puVar59;
            if (-1 < iVar107)
            {
                piVar15[1] = piVar15[1] + 1;
                pcVar24 = piVar15[2];
                goto code_r0x00002601;
            }
            iVar107 = *piVar15;
            *(puVar59 + -8) = 0x3195;
            iVar6 = sym.imp.feof(iVar107);
            if (iVar6 == 0)
            {
                pcVar113 = pcStack_1a0;
                uVar118 = 0;
                *(puVar59 + -8) = 0x31ac;
                pcVar113 = sym.quotearg_n_style_colon.constprop.0(pcVar113);
                *(puVar59 + -8) = 0x31c2;
                uVar11 = sym.imp.dcgettext(0, "%s: read error", 5);
                puVar58 = puVar59 + 0;
                *(puVar59 + 0 + -8) = 0x31ca;
                puVar26 = sym.imp.__errno_location();
                uVar7 = *puVar26;
                *(puVar58 + -8) = 0x31db;
                sym.imp.error(0, uVar7, uVar11, pcVar113);
                puVar59 = puVar58;
            }
        code_r0x000030cd:
            piVar115 = piVar15;
            puVar57 = puVar59;
            *(puVar59 + -8) = 0x30d5;
            sym.argv_iter_free(piVar115);
            *(puVar57 + -8) = 0x30e1;
            sym.di_set_free(*0x18220);
            puVar61 = puVar57;
            if (*0x18200 != NULL)
            {
                *(puVar57 + -8) = 0x30f2;
                sym.di_set_free();
                puVar61 = puVar57 + 0;
            }
            if (pcStack_1a0 != NULL)
            {
                if ((**_reloc.stdin & 0x20) == 0)
                {
                    *(puVar61 + -8) = 0x36c7;
                    iVar6 = sym.rpl_fclose();
                    puVar61 = puVar61;
                    if (iVar6 == 0)
                        goto code_r0x00003118;
                }
                if (uVar118 != 0)
                {
                    pcVar24 = pcStack_1a0;
                    puVar98 = puVar61;
                    *(puVar61 + -8) = 0x4371;
                    piVar19 = sym.quotearg_style.constprop.0(pcVar24);
                    *(puVar98 + -8) = 0x4387;
                    uVar11 = sym.imp.dcgettext(0, "error reading %s", 5);
                    puVar61 = puVar98;
                    if (iStack_40 != *(in_FS_OFFSET + 0x28))
                        goto code_r0x0000254a;
                    *(puVar98 + -8) = 0x43ae;
                    sym.imp.error(1, 0, uVar11, piVar19);
                    puVar99 = puVar98 + 0;
                code_r0x000043ae:
                    *(puVar99 + -8) = 0x43c1;
                    uVar11 = sym.imp.dcgettext(0, "fts_close failed", 5);
                    iVar6 = *piVar19;
                    *(puVar99 + -8) = 0x43cf;
                    sym.imp.error(0, iVar6, uVar11);
                    puVar59 = puVar99;
                    uStack_1a1 = 0;
                code_r0x000030ad:
                    uVar118 = uVar118 & uStack_1a1;
                    goto code_r0x000025d4;
                }
            }
        code_r0x00003118:
            if (*0x18249 != '\0')
            {
                *(puVar61 + -8) = 0x3241;
                uVar11 = sym.imp.dcgettext(0, "total", 5);
                *(puVar61 + -8) = 0x3250;
                sym.print_size(0x181e0, uVar11);
                puVar61 = puVar61;
            }
            if (iStack_40 == *(in_FS_OFFSET + 0x28))
            {
                return uVar118 ^ 1;
            }
            goto code_r0x0000254a;
        }
    }
code_r0x00003bb6:
    if (iStack_40 == *(in_FS_OFFSET + 0x28))
    {
        // WARNING: Subroutine does not return
        *(puVar61 + -8) = 0x3bce;
        sym.xalloc_die();
    }
code_r0x0000254a:
    // WARNING: Subroutine does not return
    *(puVar61 + -8) = 0x254f;
    sym.imp.__stack_chk_fail();
}

// sym.atexit
void sym.atexit(ulong param_1)

{
    // WARNING: Could not recover jumptable at 0x00001b74. Too many branches
    // WARNING: Treating indirect jump as call
    (*_reloc.__cxa_atexit)(param_1, 0, *0x17620);
    return;
}
