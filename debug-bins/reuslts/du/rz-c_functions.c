// sym._init
// WARNING: [rz-ghidra] Detected overlap for variable var_32h
// WARNING: [rz-ghidra] Detected overlap for variable var_31h

void sym._init(void)
{
    if (_reloc.__gmon_start != (code *)0x0) {
        (*_reloc.__gmon_start)();
    }
    return;
}



// main
// WARNING: Variable defined which should be unmapped: var_30h
// WARNING: [rz-ghidra] Detected overlap for variable var_32h
// WARNING: [rz-ghidra] Detected overlap for variable var_31h
// WARNING: [rz-ghidra] Detected overlap for variable var_1a1h
// WARNING: [rz-ghidra] Detected overlap for variable var_1a2h
// WARNING: [rz-ghidra] Detected overlap for variable var_1a8h
// WARNING: [rz-ghidra] Detected overlap for variable var_130h
// WARNING: [rz-ghidra] Detected overlap for variable var_134h
// WARNING: [rz-ghidra] Detected overlap for variable var_128h
// WARNING: [rz-ghidra] Detected overlap for variable var_164h
// WARNING: [rz-ghidra] Detected overlap for variable var_160h
// WARNING: [rz-ghidra] Detected overlap for variable var_44h
// WARNING: [rz-ghidra] Detected overlap for variable var_a8h
// WARNING: [rz-ghidra] Detected overlap for variable var_58h
// WARNING: [rz-ghidra] Detected overlap for variable var_4ch
// WARNING: [rz-ghidra] Detected overlap for variable var_6ch

uint32_t main(int argc, char **argv)
{
    undefined4 uVar1;
    uint64_t uVar2;
    undefined8 *puVar3;
    uint64_t uVar4;
    undefined4 uVar5;
    undefined4 uVar6;
    uint8_t **ppuVar7;
    char cVar8;
    int32_t iVar9;
    int32_t iVar10;
    uint32_t uVar11;
    int64_t iVar12;
    FILE *pFVar13;
    int64_t iVar14;
    int64_t arg6;
    int64_t arg5;
    undefined4 *puVar15;
    void **ptr;
    uint64_t arg1;
    int64_t *piVar16;
    undefined *puVar17;
    int64_t **ppiVar18;
    int64_t iVar19;
    uint64_t uVar20;
    uint64_t *puVar21;
    int32_t *piVar22;
    int64_t *piVar23;
    char *pcVar24;
    uint8_t *puVar25;
    undefined *puVar26;
    undefined *puVar27;
    char **ppcVar28;
    char *pcVar29;
    undefined8 uVar30;
    int64_t *piVar31;
    undefined8 uVar32;
    int64_t **ppiVar33;
    uint64_t uVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint16_t uVar37;
    char *pcVar38;
    char *pcVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint8_t uVar43;
    code *pcVar44;
    uint64_t uVar45;
    undefined8 *puVar46;
    int64_t *piVar47;
    code cVar48;
    void **ppvVar49;
    int64_t in_FS_OFFSET;
    bool bVar50;
    char cVar51;
    char cVar52;
    bool bVar53;
    int64_t extraout_XMM0_Qa;
    int64_t extraout_XMM0_Qa_00;
    int64_t arg7;
    int64_t extraout_XMM0_Qa_01;
    undefined8 extraout_XMM0_Qa_02;
    undefined8 extraout_XMM0_Qa_03;
    int64_t extraout_XMM0_Qa_04;
    int64_t extraout_XMM0_Qa_05;
    int64_t arg7_00;
    undefined8 extraout_XMM0_Qa_06;
    int64_t arg7_01;
    int64_t extraout_XMM0_Qa_07;
    int64_t extraout_XMM0_Qa_08;
    int64_t extraout_XMM0_Qa_09;
    int64_t extraout_XMM0_Qa_10;
    int64_t extraout_XMM0_Qa_11;
    int64_t extraout_XMM0_Qa_12;
    int64_t extraout_XMM0_Qa_13;
    int64_t extraout_XMM0_Qa_14;
    uint64_t uVar54;
    undefined in_XMM1 [16];
    undefined in_XMM2 [16];
    uint64_t uVar55;
    int64_t in_XMM3_Qa;
    int64_t in_XMM4_Qa;
    undefined8 in_XMM6_Qa;
    undefined8 in_XMM7_Qa;
    int64_t var_1c8h;
    int64_t var_1c0h;
    int64_t var_1b8h;
    int64_t var_1b0h;
    undefined var_1a1h;
    char *filename;
    int64_t var_198h;
    int64_t var_190h;
    int64_t var_188h;
    int64_t var_180h;
    uint64_t var_178h;
    uint64_t var_170h;
    FILE *var_168h;
    uint64_t var_158h;
    int64_t var_148h;
    char *s;
    uint32_t var_134h;
    uint32_t var_130h;
    int64_t var_12ch;
    int64_t var_120h;
    char *var_118h;
    int64_t var_110h;
    int64_t var_108h;
    int64_t var_100h;
    int64_t var_f8h;
    uint64_t uStack_f0;
    int64_t var_e8h;
    int64_t var_e0h;
    int64_t var_d8h;
    int64_t var_d0h;
    int64_t canary;
    int64_t var_30h;
    
    pcVar24 = *argv;
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_e0h = 0;
    var_e8h = (int64_t)data.00012f7e;
    if (pcVar24 == (char *)0x0) {
        sym.imp.fwrite("A NULL argv[0] was passed through an exec system call.\n", 1, 0x37, *_reloc.stderr);
    // WARNING: Subroutine does not return
        sym.imp.abort();
    }
    iVar12 = sym.imp.strrchr(pcVar24, 0x2f);
    if ((((iVar12 != 0) && (pcVar38 = (char *)(iVar12 + 1), 6 < (int64_t)pcVar38 - (int64_t)pcVar24)) &&
        (iVar9 = sym.imp.strncmp(iVar12 + -6, "/.libs/", 7), iVar9 == 0)) &&
       (iVar9 = sym.imp.strncmp(pcVar38, data.00013032, 3), pcVar24 = pcVar38, iVar9 == 0)) {
        pcVar24 = (char *)(iVar12 + 4);
        *_reloc.program_invocation_short_name = pcVar24;
    }
    _data.00018280 = pcVar24;
    *_reloc.program_invocation_name = pcVar24;
    sym.imp.setlocale(6, data.00012f50);
    sym.imp.bindtextdomain(data.00012de4, "/usr/share/locale");
    sym.imp.textdomain(data.00012de4);
    sym.atexit(sym.close_stdout);
    _data.00018250 = (int64_t **)sym.new_exclude();
    iVar12 = sym.imp.getenv("DU_BLOCK_SIZE");
    sym.human_options.constprop.0(iVar12);
    bVar50 = false;
    s = "\x03";
    var_158h = 8;
    filename = (char *)0x0;
    var_170h = 1;
    bVar53 = false;
code_r0x00001e70:
    do {
        var_110h = CONCAT44(var_110h._4_4_, 0xffffffff);
        iVar9 = sym.imp.getopt_long(argc, argv, "0abd:chHklmst:xB:DLPSX:", data.000176c0);
        ppiVar33 = _data.00018250;
        iVar19 = in_XMM2._0_8_;
        iVar12 = in_XMM1._0_8_;
        if (iVar9 == -1) {
            if (var_170h._0_1_ == (code)0x0) goto code_r0x00004280;
            if (data.0001824b == (code)0x0) {
                if (bVar53) {
                    if (bVar50) {
                        if (_data.00018028 == 0) {
                            uVar30 = sym.imp.dcgettext(0, "warning: summarizing is the same as using --max-depth=0", 5);
                            sym.imp.error(0, 0, uVar30);
                            if (_data.00018028 == 0) goto code_r0x0000321f;
                        }
                        uVar42 = _data.00018028;
                        uVar30 = sym.imp.dcgettext(0, "warning: summarizing conflicts with --max-depth=%td", 5);
                        sym.imp.error(0, 0, uVar30, uVar42);
                        if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) goto code_r0x0000254a;
                        goto code_r0x00003c47;
                    }
                } else if (bVar50) {
code_r0x0000321f:
                    _data.00018028 = 0;
                }
            } else if (bVar50) {
                uVar30 = sym.imp.dcgettext(0, "cannot both summarize and show all entries", 5);
                sym.imp.error(0, 0, uVar30);
                if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) goto code_r0x00003c47;
                goto code_r0x0000254a;
            }
            if (data.00018271 != (code)0x0) {
                if (data.0001824a != (code)0x0) {
                    uVar30 = sym.imp.dcgettext(0, 
                                               "warning: options --apparent-size and -b are ineffective with --inodes", 
                                               5);
                    sym.imp.error(0, 0, uVar30);
                }
                _data.00018278 = 1;
            }
            if (data.00018270 == (code)0x0) goto code_r0x000023d7;
            pcVar24 = _data.00018230;
            if (_data.00018230 != (char *)0x0) goto code_r0x000023c2;
            pcVar24 = (char *)sym.imp.getenv("TIME_STYLE");
            if ((pcVar24 == (char *)0x0) ||
               (_data.00018230 = pcVar24, iVar9 = sym.imp.strcmp(pcVar24, "locale"), iVar9 == 0)) {
                pcVar24 = "long-iso";
                _data.00018230 = "long-iso";
                goto code_r0x000036e2;
            }
            pcVar38 = pcVar24;
            pcVar39 = _data.00018230;
            if (*pcVar24 != '+') break;
            puVar17 = (undefined *)sym.imp.strchr(pcVar24, 10);
            if (puVar17 == (undefined *)0x0) goto code_r0x000023cc;
            *puVar17 = 0;
            goto code_r0x000023c2;
        }
        if (0x87 < iVar9) {
code_r0x00001ed0:
            var_170h = 0;
            goto code_r0x00001e70;
        }
        if (iVar9 < 0x30) {
            if (iVar9 == -0x83) {
                sym.proper_name_lite(0x1309c, 0x1309c);
                iVar14 = sym.proper_name_lite(0x130a9, 0x130a9);
                arg6 = sym.proper_name_lite(0x130b5, 0x130b5);
                arg5 = sym.proper_name_lite(0x130d8, 0x130c5);
                sym.version_etc.constprop.0
                          (arg7, iVar12, iVar19, in_XMM3_Qa, in_XMM4_Qa, *_reloc.stdout, in_XMM6_Qa, in_XMM7_Qa, 0x130ea
                           , arg5, arg6, iVar14);
    // WARNING: Subroutine does not return
                sym.imp.exit(0);
            }
            if (iVar9 != -0x82) goto code_r0x00001ed0;
            if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
                sym.usage(0);
            }
            goto code_r0x0000254a;
        }
    // switch table (88 cases) at 0x14f90
        switch(iVar9) {
        case 0x30:
            data.00018258 = (code)0x1;
            break;
        default:
            goto code_r0x00001ed0;
        case 0x42:
            goto code_r0x00001ee5;
        case 0x44:
        case 0x48:
            s = "";
            break;
        case 0x4c:
            s = "LF\x02\x01\x01";
            break;
        case 0x50:
            s = "\x03";
            break;
        case 0x53:
            data.0001823c = (code)0x1;
            break;
        case 0x58:
            pcVar24 = *_reloc.optarg;
            stack0xfffffffffffffed8 = sym.add_exclude;
            iVar9 = sym.imp.strcmp(pcVar24, data.00012ea9);
            if (iVar9 == 0) {
                iVar9 = sym.add_exclude_fp.constprop.0
                                  ((int64_t)ppiVar33, (int64_t)*_reloc.stdin, 10, (int64_t)&var_12ch + 4);
                iVar12 = extraout_XMM0_Qa_01;
code_r0x00001ff5:
                if (iVar9 == 0) break;
            } else {
                pFVar13 = (FILE *)sym.rpl_fopen.constprop.0((int64_t)pcVar24);
                iVar12 = extraout_XMM0_Qa;
                if (pFVar13 != (FILE *)0x0) {
                    iVar9 = sym.add_exclude_fp.constprop.0
                                      ((int64_t)ppiVar33, (int64_t)pFVar13, 10, (int64_t)&var_12ch + 4);
                    puVar15 = (undefined4 *)sym.imp.__errno_location();
                    uVar1 = *puVar15;
                    iVar10 = sym.rpl_fclose(pFVar13);
                    iVar12 = extraout_XMM0_Qa_00;
                    if (-1 < iVar10) {
                        *puVar15 = uVar1;
                        goto code_r0x00001ff5;
                    }
                }
            }
            uVar30 = sym.quotearg_n_style_colon.constprop.0(iVar12, *_reloc.optarg);
            puVar15 = (undefined4 *)sym.imp.__errno_location();
            sym.imp.error(0, *puVar15, data.00012fe5, uVar30);
            var_170h = 0;
            break;
        case 0x61:
            data.0001824b = (code)0x1;
            break;
        case 0x62:
            data.0001824a = (code)0x1;
            _data.00018274 = 0;
            _data.00018278 = 1;
            break;
        case 99:
            data.00018249 = (code)0x1;
            break;
        case 100:
            iVar9 = sym.xstrtoimax.constprop.0((int64_t)*_reloc.optarg, (int64_t)&var_108h, 0x12f50);
            if (iVar9 == 0) {
                _data.00018028 = var_108h;
                bVar53 = true;
            } else {
                uVar30 = sym.quotearg_n_options.constprop.0(0, (int64_t)*_reloc.optarg, 0x18040);
                uVar32 = sym.imp.dcgettext(0, "invalid maximum depth %s", 5);
                sym.imp.error(0, 0, uVar32, uVar30);
                var_170h = 0;
            }
            break;
        case 0x68:
            _data.00018274 = 0xb0;
            _data.00018278 = 1;
            break;
        case 0x6b:
            _data.00018278 = 0x400;
            _data.00018274 = 0;
            break;
        case 0x6c:
            data.00018248 = (code)0x1;
            break;
        case 0x73:
            bVar50 = true;
            break;
        case 0x74:
            uVar11 = sym.xstrtoimax.constprop.0((int64_t)*_reloc.optarg, 0x18240, 0x13087);
            if (uVar11 != 0) {
                if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
                    sym.xstrtol_fatal.constprop.0
                              ((uint64_t)uVar11, var_110h & 0xffffffff, in_XMM2._0_8_, (int64_t)*_reloc.optarg);
                }
                goto code_r0x0000254a;
            }
            if ((_data.00018240 != 0) || (**_reloc.optarg != '-')) break;
            uVar30 = sym.imp.dcgettext(0, "invalid --threshold argument \'-0\'", 5);
            if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) goto code_r0x0000254a;
            sym.imp.error(1, 0, uVar30);
        case 0x6d:
            _data.00018278 = 0x100000;
            _data.00018274 = 0;
            break;
        case 0x78:
            var_158h = 0x48;
            break;
        case 0x80:
            data.0001824a = (code)0x1;
            break;
        case 0x81:
            sym.add_exclude((int64_t)_data.00018250, (int64_t)*_reloc.optarg, 0x10000000);
            break;
        case 0x82:
            filename = *_reloc.optarg;
            break;
        case 0x83:
            _data.00018274 = 0x90;
            _data.00018278 = 1;
            break;
        case 0x85:
            data.00018270 = (code)0x1;
            iVar9 = 0;
            if (*_reloc.optarg != (char *)0x0) {
                iVar12 = sym.__xargmatch_internal.constprop.0
                                   (0x13095, (int64_t)*_reloc.optarg, 0x17680, 0x151e0, 0x4e50);
                iVar9 = *(int32_t *)(data.000151e0 + iVar12 * 4);
            }
            _data.00018238 = iVar9;
            iVar12 = sym.imp.getenv(data.00012ed0);
            _data.00018268 = sym.tzalloc(iVar12);
            break;
        case 0x86:
            _data.00018230 = *_reloc.optarg;
            break;
        case 0x87:
            data.00018271 = (code)0x1;
        }
    } while( true );
    do {
        _data.00018230 = pcVar39;
        pcVar24 = pcVar38;
        iVar9 = sym.imp.strncmp(pcVar24, "posix-", 6);
        pcVar38 = pcVar24 + 6;
        pcVar39 = pcVar24 + 6;
    } while (iVar9 == 0);
code_r0x000023c2:
    if (*pcVar24 == '+') {
code_r0x000023cc:
        _data.00018260 = pcVar24 + 1;
    } else {
code_r0x000036e2:
        iVar12 = sym.__xargmatch_internal.constprop.0(0x130f9, (int64_t)pcVar24, 0x17660, 0x151c8, 0x4e50);
        iVar9 = *(int32_t *)(data.000151c8 + iVar12 * 4);
        if (iVar9 == 1) {
            _data.00018260 = "%Y-%m-%d %H:%M";
        } else {
            if (iVar9 == 2) goto code_r0x00003957;
            if (iVar9 == 0) {
                _data.00018260 = "%Y-%m-%d %H:%M:%S.%N %z";
            }
        }
    }
code_r0x000023d7:
    do {
        piVar22 = _reloc.optind;
        iVar9 = *_reloc.optind;
        if (filename == (char *)0x0) goto code_r0x00003255;
        if (iVar9 < argc) {
            uVar30 = sym.quotearg_n_options.constprop.0(0, (int64_t)argv[iVar9], 0x18040);
            uVar32 = sym.imp.dcgettext(0, "extra operand %s", 5);
            sym.imp.error(0, 0, uVar32, uVar30);
            uVar30 = sym.imp.dcgettext(0, "file operands cannot be combined with --files0-from", 5);
            sym.imp.__fprintf_chk(*_reloc.stderr, 2, data.00012f06, uVar30);
code_r0x00004280:
            if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
code_r0x00003c47:
    // WARNING: Subroutine does not return
                sym.usage(1);
            }
            goto code_r0x0000254a;
        }
        iVar9 = sym.imp.strcmp(filename, data.00012ea9);
        ppuVar7 = _reloc.stdin;
        if (iVar9 == 0) {
code_r0x00002562:
            ptr = (void **)sym.argv_iter_init_stream((int64_t)*ppuVar7);
            cVar48 = var_170h._0_1_;
            goto code_r0x00002574;
        }
        puVar25 = *_reloc.stdin;
        iVar9 = sym.imp.fileno();
        if (iVar9 == 1) {
            iVar9 = sym.imp.dup2(0, 0);
            if (iVar9 != 0) {
                cVar51 = false;
                cVar52 = false;
                goto code_r0x000039d7;
            }
            argc = 0;
            cVar51 = '\0';
            cVar8 = '\0';
code_r0x000038af:
            cVar52 = cVar8;
            var_168h = (FILE *)sym.imp.freopen(filename, "r", puVar25);
code_r0x000038cc:
            puVar15 = (undefined4 *)sym.imp.__errno_location();
            var_178h._0_4_ = *puVar15;
            if (cVar51 != '\0') {
code_r0x000024ce:
                sym.imp.close(2);
            }
            if (cVar52 != '\0') goto code_r0x000039a5;
        } else {
            if (iVar9 == 2) {
                cVar51 = false;
            } else {
                if (iVar9 == 0) {
                    cVar51 = '\0';
                    argc = 0;
                    cVar8 = '\0';
                    goto code_r0x000038af;
                }
                iVar9 = sym.imp.dup2(2, 2);
                cVar51 = iVar9 != 2;
            }
            iVar9 = sym.imp.dup2(1, 1);
            cVar52 = iVar9 != 1;
            argc = 0;
            iVar9 = sym.imp.dup2(0, 0);
            cVar8 = cVar52;
            if (iVar9 != 0) {
code_r0x000039d7:
                argc = sym.protect_fd(0);
                cVar8 = cVar52;
                if ((char)argc != '\0') goto code_r0x0000247f;
                argc = (int)(uint8_t)var_170h._0_1_;
                var_168h = (FILE *)0x0;
                goto code_r0x000038cc;
            }
code_r0x0000247f:
            cVar52 = cVar51;
            if (((bool)cVar8 == false) || (cVar8 = sym.protect_fd(1), cVar8 != '\0')) {
                cVar51 = cVar52;
                if (((bool)cVar52 == false) || (cVar51 = sym.protect_fd(2), cVar51 != '\0')) goto code_r0x000038af;
                puVar15 = (undefined4 *)sym.imp.__errno_location();
                var_178h._0_4_ = *puVar15;
                var_168h = (FILE *)0x0;
                cVar52 = cVar8;
                goto code_r0x000024ce;
            }
            puVar15 = (undefined4 *)sym.imp.__errno_location();
            var_178h._0_4_ = *puVar15;
            if ((bool)cVar52 != false) {
                var_168h = (FILE *)0x0;
                goto code_r0x000024ce;
            }
            var_168h = (FILE *)0x0;
code_r0x000039a5:
            sym.imp.close(1);
        }
        if ((char)argc != '\0') {
            sym.imp.close(0);
        }
        if (var_168h != (FILE *)0x0) goto code_r0x00002562;
        *puVar15 = (undefined4)var_178h;
        argv = (char **)sym.quotearg_style.constprop.0(filename);
        uVar30 = sym.imp.dcgettext(0, "cannot open %s for reading", 5);
        if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) goto code_r0x0000254a;
        sym.imp.error(1, *puVar15, uVar30, argv);
code_r0x00003957:
        _data.00018260 = "%Y-%m-%d";
    } while( true );
code_r0x0000279d:
    cVar48 = (code)0x0;
code_r0x000027a0:
    iVar12 = sym.imp.free(iVar19);
    if ((code)(*(uint8_t *)((int64_t)ppiVar33 + 0xf) >> 5 & 1 ^ 1) != cVar48) {
code_r0x000027cc:
        cVar48 = var_170h._0_1_;
        if (uVar37 == 1) {
            *(undefined2 *)((int64_t)piVar16 + 0x6c) = 4;
            piVar23 = (int64_t *)sym.rpl_fts_read(arg1);
            if (piVar16 != piVar23) {
    // WARNING: Subroutine does not return
                sym.imp.__assert_fail("e == ent", "../src/du.c", 0x22e, "process_file");
            }
        }
        goto code_r0x000027dd;
    }
code_r0x00002a24:
    if (uVar37 == 0xb) {
        *(undefined2 *)((int64_t)piVar16 + 0x6c) = 1;
        piVar23 = (int64_t *)sym.rpl_fts_read(arg1);
        if (piVar16 != piVar23) {
    // WARNING: Subroutine does not return
            sym.imp.__assert_fail("e == ent", "../src/du.c", 0x20d, "process_file");
        }
        uVar37 = *(uint16_t *)(piVar16 + 0xd);
        iVar12 = extraout_XMM0_Qa_07;
    }
    pFVar13 = _data.00018220;
    cVar48 = (code)(uVar37 == 10 || uVar37 == 0xd);
    if ((bool)cVar48) {
        sym.quotearg_style.constprop.0(pcVar38);
        uVar30 = sym.imp.dcgettext(0, "cannot access %s", 5);
        sym.imp.error(0, *(undefined4 *)(piVar16 + 8), uVar30);
code_r0x0000389f:
        cVar48 = (code)0x0;
        goto code_r0x000027dd;
    }
    if ((((*(uint8_t *)(arg1 + 0x48) & 0x40) != 0) && (0 < piVar16[0xb])) && (*(int64_t *)(arg1 + 0x18) != piVar16[0xe])
       ) goto code_r0x000027cc;
    if ((data.00018248 == (code)0x0) &&
       ((data.00018228 != (code)0x0 ||
        (((*(uint32_t *)(piVar16 + 0x11) & 0xf000) != 0x4000 && (1 < (uint64_t)piVar16[0x10])))))) {
        iVar12 = piVar16[0xf];
        iVar19 = sym.map_device((int64_t)_data.00018220, piVar16[0xe]);
        if ((iVar19 == 0) ||
           ((iVar12 = sym.map_inode_number(pFVar13, iVar12), iVar12 == -1 ||
            (iVar9 = sym.hash_insert_if_absent(iVar19, iVar12, 0), iVar9 == -1)))) goto code_r0x00003bb6;
        iVar12 = extraout_XMM0_Qa_05;
        if (iVar9 == 0) goto code_r0x000027cc;
    }
    if (uVar37 == 2) {
        uVar11 = *(uint32_t *)(arg1 + 0x48) & 0x11;
        if ((uVar11 != 0x10) && ((cVar48 = var_170h._0_1_, uVar11 != 0x11 || (piVar16[0xb] == 0))))
        goto code_r0x000027dd;
        piVar23 = (int64_t *)*piVar16;
        if (_data.00018200 == (FILE *)0x0) {
            _data.00018200 = (FILE *)sym.di_set_alloc();
            if (_data.00018200 == (FILE *)0x0) goto code_r0x00003bb6;
            puVar25 = (uint8_t *)sym.rpl_fopen.constprop.0(0x131e2);
            puVar46 = (undefined8 *)0x0;
            if (puVar25 == (uint8_t *)0x0) {
                iVar19 = sym.imp.setmntent("/etc/mtab");
                iVar12 = extraout_XMM0_Qa_12;
                if (iVar19 != 0) {
                    var_158h = (uint64_t)&var_120h;
                    while (piVar31 = (int64_t *)sym.imp.getmntent(iVar19), piVar31 != (int64_t *)0x0) {
                        iVar12 = sym.imp.hasmntopt(piVar31, "bind");
                        ppcVar28 = (char **)sym.imp.malloc(0x38);
                        if (ppcVar28 == (char **)0x0) goto code_r0x00003bb6;
                        bVar50 = true;
                        pcVar39 = (char *)sym.xstrdup(*piVar31);
                        *ppcVar28 = pcVar39;
                        pcVar39 = (char *)sym.xstrdup(piVar31[1]);
                        ppcVar28[2] = (char *)0x0;
                        ppcVar28[1] = pcVar39;
                        pcVar39 = (char *)sym.xstrdup(piVar31[2]);
                        *(uint8_t *)(ppcVar28 + 5) = *(uint8_t *)(ppcVar28 + 5) | 4;
                        ppcVar28[3] = pcVar39;
                        iVar9 = sym.imp.strcmp(pcVar39, "autofs");
                        if ((((((iVar9 != 0) && (iVar9 = sym.imp.strcmp(pcVar39, "proc"), iVar9 != 0)) &&
                              (iVar9 = sym.imp.strcmp(pcVar39, "subfs"), iVar9 != 0)) &&
                             (((iVar9 = sym.imp.strcmp(pcVar39, "debugfs"), iVar9 != 0 &&
                               (iVar9 = sym.imp.strcmp(pcVar39, "devpts"), iVar9 != 0)) &&
                              (((iVar9 = sym.imp.strcmp(pcVar39, "fusectl"), iVar9 != 0 &&
                                ((iVar9 = sym.imp.strcmp(pcVar39, "fuse.portal"), iVar9 != 0 &&
                                 (iVar9 = sym.imp.strcmp(pcVar39, "mqueue"), iVar9 != 0)))) &&
                               (iVar9 = sym.imp.strcmp(pcVar39, "rpc_pipefs"), iVar9 != 0)))))) &&
                            (((iVar9 = sym.imp.strcmp(pcVar39, "sysfs"), iVar9 != 0 &&
                              (iVar9 = sym.imp.strcmp(pcVar39, "devfs"), iVar9 != 0)) &&
                             (iVar9 = sym.imp.strcmp(pcVar39, "kernfs"), iVar9 != 0)))) &&
                           (iVar9 = sym.imp.strcmp(pcVar39, "ignore"), iVar9 != 0)) {
                            iVar9 = sym.imp.strcmp(pcVar39, "none");
                            bVar50 = iVar12 == 0 && iVar9 == 0;
                        }
                        bVar53 = true;
                        pcVar29 = *ppcVar28;
                        *(uint8_t *)(ppcVar28 + 5) = *(uint8_t *)(ppcVar28 + 5) & 0xfe | bVar50;
                        iVar12 = sym.imp.strchr(pcVar29);
                        if ((iVar12 == 0) &&
                           (((*pcVar29 != '/' || (pcVar29[1] != '/')) ||
                            ((iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0 &&
                             ((iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0 &&
                              (iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0)))))))) {
                            bVar53 = true;
                            iVar9 = sym.imp.strcmp(pcVar39);
                            if ((iVar9 != 0) &&
                               ((((((iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0 &&
                                    (iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0)) &&
                                   (iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0)) &&
                                  ((iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0 &&
                                   (iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0)))) &&
                                 (iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0)) &&
                                ((iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0 &&
                                 (iVar9 = sym.imp.strcmp(pcVar39), iVar9 != 0)))))) {
                                iVar9 = sym.imp.strcmp("-hosts");
                                bVar53 = iVar9 == 0;
                            }
                        }
                        ppcVar28[4] = (char *)0xffffffffffffffff;
                        *(uint8_t *)(ppcVar28 + 5) = *(uint8_t *)(ppcVar28 + 5) & 0xfd | bVar53 * '\x02';
                        *(char ***)var_158h = ppcVar28;
                        var_158h = (uint64_t)(ppcVar28 + 6);
                    }
                    iVar9 = sym.imp.endmntent();
                    iVar12 = extraout_XMM0_Qa_13;
                    if (iVar9 != 0) goto code_r0x00003ae6;
                    goto code_r0x000040d0;
                }
            } else {
                var_158h = (uint64_t)&var_120h;
                var_118h = (char *)0x0;
                var_110h = 0;
                while (iVar12 = sym.imp.__getdelim(&var_118h, &var_110h, 10), iVar12 != -1) {
                    iVar9 = sym.imp.__isoc23_sscanf(var_118h, "%*u %*u %u:%u %n", &var_134h, &var_130h);
                    if (iVar9 - 2U < 2) {
                        pcVar39 = var_118h + (int32_t)var_12ch;
                        puVar17 = (undefined *)sym.imp.strchr(pcVar39, 0x20);
                        if (puVar17 != (undefined *)0x0) {
                            *puVar17 = 0;
                            puVar17 = puVar17 + 1;
                            puVar26 = (undefined *)sym.imp.strchr(puVar17, 0x20);
                            if (puVar26 != (undefined *)0x0) {
                                *puVar26 = 0;
                                iVar12 = sym.imp.strstr(puVar26 + 1, data.00013208);
                                if (iVar12 != 0) {
                                    iVar12 = iVar12 + 3;
                                    puVar26 = (undefined *)sym.imp.strchr(iVar12, 0x20);
                                    if (puVar26 != (undefined *)0x0) {
                                        *puVar26 = 0;
                                        puVar26 = puVar26 + 1;
                                        puVar27 = (undefined *)sym.imp.strchr(puVar26, 0x20);
                                        if (puVar27 != (undefined *)0x0) {
                                            *puVar27 = 0;
                                            sym.unescape_tab((int64_t)puVar26);
                                            sym.unescape_tab((int64_t)puVar17);
                                            sym.unescape_tab((int64_t)pcVar39);
                                            sym.unescape_tab(iVar12);
                                            ppcVar28 = (char **)sym.imp.malloc(0x38);
                                            if (ppcVar28 == (char **)0x0) goto code_r0x00003bb6;
                                            bVar50 = true;
                                            pcVar29 = (char *)sym.xstrdup((int64_t)puVar26);
                                            *ppcVar28 = pcVar29;
                                            pcVar29 = (char *)sym.xstrdup((int64_t)puVar17);
                                            ppcVar28[1] = pcVar29;
                                            pcVar39 = (char *)sym.xstrdup((int64_t)pcVar39);
                                            ppcVar28[2] = pcVar39;
                                            pcVar39 = (char *)sym.xstrdup(iVar12);
                                            *(uint8_t *)(ppcVar28 + 5) = *(uint8_t *)(ppcVar28 + 5) | 4;
                                            ppcVar28[3] = pcVar39;
                                            ppcVar28[4] = (char *)(((uint64_t)var_130h & 0xffffff00) << 0xc |
                                                                  ((uint64_t)var_134h & 0xfffff000) << 0x20 |
                                                                  (uint64_t)((var_134h & 0xfff) << 8) |
                                                                  (uint64_t)(uint8_t)var_130h);
                                            iVar9 = sym.imp.strcmp(pcVar39, "autofs");
                                            if (((((((iVar9 != 0) &&
                                                    (iVar9 = sym.imp.strcmp(pcVar39, "proc"), iVar9 != 0)) &&
                                                   (iVar9 = sym.imp.strcmp(pcVar39, "subfs"), iVar9 != 0)) &&
                                                  (((iVar9 = sym.imp.strcmp(pcVar39, "debugfs"), iVar9 != 0 &&
                                                    (iVar9 = sym.imp.strcmp(pcVar39, "devpts"), iVar9 != 0)) &&
                                                   ((iVar9 = sym.imp.strcmp(pcVar39, "fusectl"), iVar9 != 0 &&
                                                    ((iVar9 = sym.imp.strcmp(pcVar39, "fuse.portal"), iVar9 != 0 &&
                                                     (iVar9 = sym.imp.strcmp(pcVar39, "mqueue"), iVar9 != 0)))))))) &&
                                                 (iVar9 = sym.imp.strcmp(pcVar39, "rpc_pipefs"), iVar9 != 0)) &&
                                                (((iVar9 = sym.imp.strcmp(pcVar39, "sysfs"), iVar9 != 0 &&
                                                  (iVar9 = sym.imp.strcmp(pcVar39, "devfs"), iVar9 != 0)) &&
                                                 (iVar9 = sym.imp.strcmp(pcVar39, "kernfs"), iVar9 != 0)))) &&
                                               (iVar9 = sym.imp.strcmp(pcVar39, "ignore"), iVar9 != 0)) {
                                                iVar9 = sym.imp.strcmp(pcVar39, "none");
                                                bVar50 = iVar9 == 0;
                                            }
                                            bVar53 = true;
                                            pcVar29 = *ppcVar28;
                                            *(uint8_t *)(ppcVar28 + 5) = *(uint8_t *)(ppcVar28 + 5) & 0xfe | bVar50;
                                            iVar12 = sym.imp.strchr(pcVar29, 0x3a);
                                            if ((iVar12 == 0) &&
                                               (((*pcVar29 != '/' || (pcVar29[1] != '/')) ||
                                                ((iVar9 = sym.imp.strcmp(pcVar39, "smbfs"), iVar9 != 0 &&
                                                 ((iVar9 = sym.imp.strcmp(pcVar39, "smb3"), iVar9 != 0 &&
                                                  (iVar9 = sym.imp.strcmp(pcVar39, "cifs"), iVar9 != 0)))))))) {
                                                bVar53 = true;
                                                iVar9 = sym.imp.strcmp(pcVar39, "acfs");
                                                if ((iVar9 != 0) &&
                                                   (((((iVar9 = sym.imp.strcmp(pcVar39, data.00013287), iVar9 != 0 &&
                                                       (iVar9 = sym.imp.strcmp(pcVar39, "coda"), iVar9 != 0)) &&
                                                      (iVar9 = sym.imp.strcmp(pcVar39, "auristorfs"), iVar9 != 0)) &&
                                                     ((iVar9 = sym.imp.strcmp(pcVar39, "fhgfs"), iVar9 != 0 &&
                                                      (iVar9 = sym.imp.strcmp(pcVar39, "gpfs"), iVar9 != 0)))) &&
                                                    ((iVar9 = sym.imp.strcmp(pcVar39, "ibrix"), iVar9 != 0 &&
                                                     ((iVar9 = sym.imp.strcmp(pcVar39, "ocfs2"), iVar9 != 0 &&
                                                      (iVar9 = sym.imp.strcmp(pcVar39, "vxfs"), iVar9 != 0)))))))) {
                                                    iVar9 = sym.imp.strcmp("-hosts", pcVar29);
                                                    bVar53 = iVar9 == 0;
                                                }
                                            }
                                            *(uint8_t *)(ppcVar28 + 5) =
                                                 *(uint8_t *)(ppcVar28 + 5) & 0xfd | bVar53 * '\x02';
                                            *(char ***)var_158h = ppcVar28;
                                            var_158h = (uint64_t)(ppcVar28 + 6);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                sym.imp.free(var_118h);
                if ((*puVar25 & 0x20) == 0) {
                    iVar9 = sym.rpl_fclose(puVar25);
                    iVar12 = extraout_XMM0_Qa_11;
                    if (iVar9 != -1) {
code_r0x00003ae6:
                        *(undefined8 *)var_158h = 0;
                        puVar46 = (undefined8 *)var_120h;
                        goto code_r0x00003af9;
                    }
                } else {
                    puVar15 = (undefined4 *)sym.imp.__errno_location();
                    uVar1 = *puVar15;
                    sym.rpl_fclose(puVar25);
                    *puVar15 = uVar1;
                }
code_r0x000040d0:
                puVar15 = (undefined4 *)sym.imp.__errno_location();
                uVar1 = *puVar15;
                *(undefined8 *)var_158h = 0;
                iVar12 = extraout_XMM0_Qa_14;
                while (iVar19 = var_120h, var_120h != 0) {
                    iVar14 = *(int64_t *)(var_120h + 0x30);
                    sym.imp.free(*(undefined8 *)var_120h);
                    sym.imp.free(*(undefined8 *)(iVar19 + 8));
                    sym.imp.free(*(undefined8 *)(iVar19 + 0x10));
                    if ((*(uint8_t *)(iVar19 + 0x28) & 4) != 0) {
                        sym.imp.free(*(undefined8 *)(iVar19 + 0x18));
                    }
                    iVar12 = sym.imp.free(iVar19);
                    var_120h = iVar14;
                }
                *puVar15 = uVar1;
            }
code_r0x00003af9:
            while (puVar46 != (undefined8 *)0x0) {
                if ((((*(uint8_t *)(puVar46 + 5) & 3) == 0) &&
                    (iVar9 = sym.imp.stat(puVar46[1], &var_d8h), iVar12 = var_d0h, pFVar13 = _data.00018200, iVar9 == 0)
                    ) && ((iVar19 = sym.map_device((int64_t)_data.00018200, var_d8h), iVar19 == 0 ||
                          ((iVar12 = sym.map_inode_number(pFVar13, iVar12), iVar12 == -1 ||
                           (iVar9 = sym.hash_insert_if_absent(iVar19, iVar12, 0), iVar9 == -1))))))
                goto code_r0x00003bb6;
                puVar3 = (undefined8 *)puVar46[6];
                sym.imp.free(*puVar46);
                sym.imp.free(puVar46[1]);
                sym.imp.free(puVar46[2]);
                if ((*(uint8_t *)(puVar46 + 5) & 4) != 0) {
                    sym.imp.free(puVar46[3]);
                }
                iVar12 = sym.imp.free(puVar46);
                puVar46 = puVar3;
            }
        }
        for (; (pFVar13 = _data.00018200, piVar16 != (int64_t *)0x0 && (piVar23 != piVar16));
            piVar16 = (int64_t *)piVar16[1]) {
            iVar19 = piVar16[0xf];
            iVar14 = sym.map_device((int64_t)_data.00018200, piVar16[0xe]);
            iVar12 = extraout_XMM0_Qa_08;
            if ((iVar14 != 0) &&
               ((iVar19 = sym.map_inode_number(pFVar13, iVar19), iVar12 = extraout_XMM0_Qa_09, iVar19 != -1 &&
                (iVar19 = sym.hash_lookup(iVar14, iVar19), cVar48 = var_170h._0_1_, iVar12 = extraout_XMM0_Qa_10,
                iVar19 != 0)))) goto code_r0x000027dd;
        }
        sym.quotearg_n_style_colon.constprop.0(iVar12, pcVar38);
        uVar30 = sym.imp.dcgettext(0, 
                                   "WARNING: Circular directory structure.\nThis almost certainly means that you have a corrupted file system.\nNOTIFY YOUR SYSTEM MANAGER.\nThe following directory is part of the cycle:\n  %s\n"
                                   , 5);
        sym.imp.error(0, 0, uVar30);
        goto code_r0x0000389f;
    }
    if (uVar37 == 7) {
        uVar30 = sym.quotearg_n_style_colon.constprop.0(iVar12, pcVar38);
        sym.imp.error(0, *(undefined4 *)(piVar16 + 8), data.00012fe5, uVar30);
    } else {
        cVar48 = var_170h._0_1_;
        if (uVar37 == 1) goto code_r0x000027dd;
    }
code_r0x00002b20:
    uVar42 = _data.000181d8;
    if (_data.00018238 == 0) {
        uVar35 = piVar16[0x19];
        uVar55 = piVar16[0x1a];
    } else if (_data.00018238 == 2) {
        uVar35 = piVar16[0x17];
        uVar55 = piVar16[0x18];
    } else {
        uVar35 = piVar16[0x1b];
        uVar55 = piVar16[0x1c];
    }
    if (data.0001824a == (code)0x0) {
        uVar45 = piVar16[0x16] << 9;
    } else {
        uVar45 = 0;
        if ((*(uint32_t *)(piVar16 + 0x11) & 0xd000) == 0x8000) {
            uVar45 = piVar16[0x14];
            if (piVar16[0x14] < 0) {
                uVar45 = 0;
            }
        }
    }
    uVar2 = piVar16[0xb];
    if (_data.000181d0 == 0) {
        _data.000181d0 = uVar2 + 10;
        iVar12 = sym.imp.calloc(_data.000181d0, 0x40);
        if (iVar12 == 0) goto code_r0x00003bb6;
code_r0x00002c21:
        _data.000181c8 = iVar12;
        uVar42 = 1;
        uVar41 = uVar45;
        uVar20 = uVar35;
        uVar54 = uVar55;
    } else {
        iVar12 = _data.000181c8;
        if (uVar2 == _data.000181d8) goto code_r0x00002c21;
        if (_data.000181d8 < uVar2) {
            if (_data.000181d0 <= uVar2) {
                iVar12 = sym.imp.reallocarray(_data.000181c8, uVar2, 0x80);
                if (iVar12 == 0) goto code_r0x00003bb6;
                _data.000181d0 = uVar2 * 2;
                _data.000181c8 = iVar12;
            }
            uVar20 = uVar42 + 1;
            iVar12 = _data.000181c8;
            if (uVar20 <= uVar2) {
                iVar19 = uVar42 * 0x40 + _data.000181c8;
                do {
                    uVar20 = uVar20 + 1;
                    *(undefined (*) [16])(iVar19 + 0x40) = (undefined  [16])0x0;
                    *(undefined4 *)(iVar19 + 0x50) = 0;
                    *(undefined4 *)(iVar19 + 0x54) = 0x80000000;
                    *(undefined4 *)(iVar19 + 0x58) = 0xffffffff;
                    *(undefined4 *)(iVar19 + 0x5c) = 0xffffffff;
                    *(undefined (*) [16])(iVar19 + 0x60) = (undefined  [16])0x0;
                    *(undefined4 *)(iVar19 + 0x70) = 0;
                    *(undefined4 *)(iVar19 + 0x74) = 0x80000000;
                    *(undefined4 *)(iVar19 + 0x78) = 0xffffffff;
                    *(undefined4 *)(iVar19 + 0x7c) = 0xffffffff;
                    iVar19 = iVar19 + 0x40;
                    iVar12 = _data.000181c8;
                } while (uVar20 <= uVar2);
            }
            goto code_r0x00002c21;
        }
        if (uVar2 != _data.000181d8 - 1) {
    // WARNING: Subroutine does not return
            sym.imp.__assert_fail("level == prev_level - 1", "../src/du.c", 0x27c, "process_file");
        }
        puVar21 = (uint64_t *)(_data.000181c8 + _data.000181d8 * 0x40);
        uVar34 = *puVar21;
        uVar41 = uVar34 + uVar45;
        if (CARRY8(uVar34, uVar45)) {
            uVar41 = 0xffffffffffffffff;
        }
        uVar20 = puVar21[2];
        uVar54 = puVar21[3];
        uVar42 = puVar21[1] + 1;
        if (-1 < (int32_t)(((uint32_t)((int64_t)uVar54 < (int64_t)uVar55) -
                           (uint32_t)((int64_t)uVar55 < (int64_t)uVar54)) +
                          ((uint32_t)((int64_t)uVar20 < (int64_t)uVar35) - (uint32_t)((int64_t)uVar35 < (int64_t)uVar20)
                          ) * 2)) {
            uVar20 = uVar35;
            uVar54 = uVar55;
        }
        if (data.0001823c == (code)0x0) {
            uVar40 = puVar21[6];
            uVar4 = puVar21[7];
            bVar50 = CARRY8(uVar41, puVar21[4]);
            uVar36 = uVar41 + puVar21[4];
            uVar41 = 0xffffffffffffffff;
            if (!bVar50) {
                uVar41 = uVar36;
            }
            uVar42 = uVar42 + puVar21[5];
            if ((int32_t)(((uint32_t)((int64_t)uVar4 < (int64_t)uVar54) - (uint32_t)((int64_t)uVar54 < (int64_t)uVar4))
                         + ((uint32_t)((int64_t)uVar40 < (int64_t)uVar20) -
                           (uint32_t)((int64_t)uVar20 < (int64_t)uVar40)) * 2) < 0) {
                uVar20 = uVar40;
                uVar54 = uVar4;
            }
        }
        iVar12 = uVar2 * 0x40 + _data.000181c8;
        uVar40 = uVar34 + *(uint64_t *)(iVar12 + 0x20);
        if (CARRY8(uVar34, *(uint64_t *)(iVar12 + 0x20))) {
            uVar40 = 0xffffffffffffffff;
        }
        *(uint64_t *)(iVar12 + 0x20) = uVar40;
        iVar19 = puVar21[1] + *(int64_t *)(iVar12 + 0x28);
        var_168h = *(FILE **)(iVar12 + 0x38);
        *(int64_t *)(iVar12 + 0x28) = iVar19;
        var_158h = *(uint64_t *)(iVar12 + 0x30);
        if ((int32_t)(((uint32_t)((int64_t)puVar21[3] < (int64_t)var_168h) -
                      (uint32_t)((int64_t)var_168h < (int64_t)puVar21[3])) +
                     ((uint32_t)((int64_t)puVar21[2] < (int64_t)var_158h) -
                     (uint32_t)((int64_t)var_158h < (int64_t)puVar21[2])) * 2) < 0) {
            var_158h = puVar21[2];
            uVar34 = puVar21[3];
            *(uint64_t *)(iVar12 + 0x30) = var_158h;
            *(uint64_t *)(iVar12 + 0x38) = uVar34;
            var_168h = *(FILE **)(iVar12 + 0x38);
        }
        iVar14 = uVar40 + puVar21[4];
        if (CARRY8(uVar40, puVar21[4])) {
            iVar14 = -1;
        }
        *(int64_t *)(iVar12 + 0x20) = iVar14;
        *(uint64_t *)(iVar12 + 0x28) = iVar19 + puVar21[5];
        if ((int32_t)(((uint32_t)((int64_t)puVar21[7] < (int64_t)var_168h) -
                      (uint32_t)((int64_t)var_168h < (int64_t)puVar21[7])) +
                     ((uint32_t)((int64_t)puVar21[6] < (int64_t)var_158h) -
                     (uint32_t)((int64_t)var_158h < (int64_t)puVar21[6])) * 2) < 0) {
            uVar1 = *(undefined4 *)((int64_t)puVar21 + 0x34);
            uVar5 = *(undefined4 *)(puVar21 + 7);
            uVar6 = *(undefined4 *)((int64_t)puVar21 + 0x3c);
            *(undefined4 *)(iVar12 + 0x30) = *(undefined4 *)(puVar21 + 6);
            *(undefined4 *)(iVar12 + 0x34) = uVar1;
            *(undefined4 *)(iVar12 + 0x38) = uVar5;
            *(undefined4 *)(iVar12 + 0x3c) = uVar6;
        }
    }
    _data.000181d8 = uVar2;
    if ((data.0001823c == (code)0x0) || ((uVar37 & 0xfffd) != 4)) {
        puVar21 = (uint64_t *)(uVar2 * 0x40 + _data.000181c8);
        uVar34 = uVar45 + *puVar21;
        if (CARRY8(uVar45, *puVar21)) {
            uVar34 = 0xffffffffffffffff;
        }
        puVar21[1] = puVar21[1] + 1;
        *puVar21 = uVar34;
        if ((int32_t)(((uint32_t)((int64_t)uVar55 < (int64_t)puVar21[3]) -
                      (uint32_t)((int64_t)puVar21[3] < (int64_t)uVar55)) +
                     ((uint32_t)((int64_t)uVar35 < (int64_t)puVar21[2]) -
                     (uint32_t)((int64_t)puVar21[2] < (int64_t)uVar35)) * 2) < 0) {
            puVar21[2] = uVar35;
            puVar21[3] = uVar55;
        }
    }
    bVar50 = CARRY8(uVar45, _data.000181e0);
    uVar45 = uVar45 + _data.000181e0;
    _data.000181e0 = 0xffffffffffffffff;
    if (!bVar50) {
        _data.000181e0 = uVar45;
    }
    _data.000181e8 = _data.000181e8 + 1;
    if ((int32_t)(((uint32_t)((int64_t)uVar55 < (int64_t)_data.000181f8) -
                  (uint32_t)((int64_t)_data.000181f8 < (int64_t)uVar55)) +
                 ((uint32_t)((int64_t)uVar35 < (int64_t)_data.000181f0) -
                 (uint32_t)((int64_t)_data.000181f0 < (int64_t)uVar35)) * 2) < 0) {
        _data.000181f0 = uVar35;
        _data.000181f8 = uVar55;
    }
    if (((uVar37 & 0xfffd) == 4) || (data.0001824b != (code)0x0)) {
        if (_data.00018028 < uVar2) goto code_r0x000027dd;
    } else if (uVar2 != 0) goto code_r0x000027dd;
    uVar35 = uVar41;
    if (data.00018271 != (code)0x0) {
        uVar35 = uVar42;
    }
    if ((int64_t)_data.00018240 < 0) {
        if (-_data.00018240 < uVar35) goto code_r0x000027dd;
    } else if (uVar35 < _data.00018240) goto code_r0x000027dd;
    var_108h = uVar41;
    var_100h = uVar42;
    var_f8h = uVar20;
    uStack_f0 = uVar54;
    sym.print_size((int64_t)&var_108h, pcVar38);
code_r0x000027dd:
    var_1a1h = (code)((uint8_t)var_1a1h & (uint8_t)cVar48);
    goto code_r0x00002690;
code_r0x00001ee5:
    uVar11 = sym.human_options.constprop.0((int64_t)*_reloc.optarg);
    if (uVar11 != 0) goto code_r0x00001efc;
    goto code_r0x00001e70;
code_r0x00001efc:
    if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
        sym.xstrtol_fatal.constprop.0((uint64_t)uVar11, var_110h & 0xffffffff, in_XMM2._0_8_, (int64_t)*_reloc.optarg);
    }
    goto code_r0x0000254a;
code_r0x00003255:
    ppcVar28 = (char **)&var_e8h;
    if (iVar9 < argc) {
        ppcVar28 = argv + iVar9;
    }
    ptr = (void **)sym.argv_iter_init_argv((int64_t)ppcVar28);
    cVar48 = (code)(*piVar22 + 1 < argc || (uint32_t)s == 2);
code_r0x00002574:
    data.00018228 = cVar48;
    if ((ptr == (void **)0x0) || (_data.00018220 = (FILE *)sym.di_set_alloc(), _data.00018220 == (FILE *)0x0)) {
code_r0x00003bb6:
        if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
    // WARNING: Subroutine does not return
            sym.xalloc_die();
        }
    } else {
        if ((data.00018248 != (code)0x0) || (cVar48 == (code)0x0)) {
            var_158h._0_4_ = (uint32_t)var_158h | 0x100;
        }
        ppvVar49 = (void **)(uint64_t)((uint32_t)var_158h | (uint32_t)s);
        pcVar24 = filename;
        uVar42 = var_170h;
        uVar30 = extraout_XMM0_Qa_02;
code_r0x000025d4:
        while (uVar11 = (uint32_t)uVar42, *ptr == (void *)0x0) {
            ppcVar28 = (char **)ptr[5];
            if (*ppcVar28 == (char *)0x0) goto code_r0x000030cd;
            ptr[5] = ppcVar28 + 1;
            pcVar38 = *ppcVar28;
code_r0x00002601:
            if (pcVar38 == (char *)0x0) {
    // WARNING: Subroutine does not return
                sym.imp.__assert_fail("!\"unexpected error code from argv_iter\"", "../src/du.c", 0x438, "main");
            }
            if (pcVar24 == (char *)0x0) {
                if (*pcVar38 == '\0') {
                    uVar30 = sym.imp.dcgettext(0, "invalid zero-length file name", 5);
                    uVar30 = sym.imp.error(0, 0, data.00012fe5, uVar30);
                    goto code_r0x00002de8;
                }
code_r0x0000263a:
                _data.00018210 = pcVar38;
                arg1 = sym.xfts_open.constprop.0(uVar30, (uint64_t)ppvVar49 & 0xffffffff);
                uVar43 = (uint8_t)uVar42;
                var_1a1h = var_170h._0_1_;
code_r0x00002690:
                piVar16 = (int64_t *)sym.rpl_fts_read(arg1);
                if (piVar16 != (int64_t *)0x0) {
                    pcVar38 = (char *)piVar16[7];
                    uVar37 = *(uint16_t *)(piVar16 + 0xd);
                    if (uVar37 != 4) {
                        cVar48 = var_170h._0_1_;
                        if (uVar37 == 6) goto code_r0x00002b20;
                        iVar19 = 0;
                        ppiVar33 = (int64_t **)*_data.00018250;
                        iVar12 = extraout_XMM0_Qa_04;
                        if (ppiVar33 != (int64_t **)0x0) {
                            if (*(int32_t *)(ppiVar33 + 1) != 0) goto code_r0x0000283b;
code_r0x00002710:
                            if (iVar19 == 0) {
                                iVar12 = sym.imp.strlen(pcVar38);
                                iVar19 = sym.imp.malloc(iVar12 + 1);
                                if (iVar19 == 0) goto code_r0x00003bb6;
                            }
                            uVar11 = *(uint32_t *)((int64_t)ppiVar33 + 0xc);
                            piVar23 = ppiVar33[2];
                            pcVar39 = pcVar38;
                            while( true ) {
                                sym.imp.strcpy(iVar19, pcVar39);
                                iVar12 = sym.hash_lookup((int64_t)piVar23, iVar19);
                                if (iVar12 != 0) goto code_r0x0000279d;
                                if ((uVar11 & 8) != 0) {
                                    while (puVar17 = (undefined *)sym.imp.strrchr(iVar19, 0x2f),
                                          puVar17 != (undefined *)0x0) {
                                        *puVar17 = 0;
                                        iVar12 = sym.hash_lookup((int64_t)piVar23, iVar19);
                                        if (iVar12 != 0) goto code_r0x0000279d;
                                    }
                                }
                                if (((uVar11 & 0x40000000) != 0) ||
                                   (iVar12 = sym.imp.strchr(pcVar39, 0x2f), iVar12 == 0)) break;
                                pcVar39 = (char *)(iVar12 + 1);
                            }
                            while (ppiVar18 = (int64_t **)*ppiVar33, ppiVar18 != (int64_t **)0x0) {
                                while( true ) {
                                    ppiVar33 = ppiVar18;
                                    if (*(int32_t *)(ppiVar18 + 1) == 0) goto code_r0x00002710;
code_r0x0000283b:
                                    piVar23 = ppiVar33[4];
                                    if ((int64_t)piVar23 < 1) break;
                                    piVar47 = ppiVar33[2] + 1;
                                    piVar31 = (int64_t *)0x0;
                                    do {
                                        uVar11 = *(uint32_t *)(piVar47 + -1);
                                        if ((uVar11 & 0x8000000) == 0) {
                                            iVar12 = *piVar47;
                                            pcVar44 = sym.fnmatch_no_wildcards;
                                            if ((uVar11 & 0x10000000) != 0) {
                                                pcVar44 = _reloc.fnmatch;
                                            }
                                            iVar9 = (*pcVar44)(iVar12, pcVar38, uVar11);
                                            bVar50 = iVar9 == 0;
                                            if ((uVar11 & 0x40000000) == 0) {
                                                cVar52 = *pcVar38;
                                                pcVar39 = pcVar38;
                                                while (cVar52 != '\0') {
                                                    if (bVar50) goto code_r0x0000279d;
                                                    do {
                                                        while( true ) {
                                                            cVar51 = pcVar39[1];
                                                            pcVar39 = pcVar39 + 1;
                                                            if (cVar52 == '/') break;
                                                            cVar52 = cVar51;
                                                            if (cVar51 == '\0') goto code_r0x0000289c;
                                                        }
                                                    } while (cVar51 == '/');
                                                    iVar9 = (*pcVar44)(iVar12, pcVar39, uVar11);
                                                    bVar50 = iVar9 == 0;
                                                    cVar52 = *pcVar39;
                                                }
                                            }
                                            if (bVar50) goto code_r0x0000279d;
                                        } else {
                                            iVar9 = sym.imp.regexec(piVar47, pcVar38, 0, 0);
                                            if (iVar9 == 0) goto code_r0x0000279d;
                                        }
code_r0x0000289c:
                                        piVar31 = (int64_t *)((int64_t)piVar31 + 1);
                                        piVar47 = piVar47 + 9;
                                    } while (piVar23 != piVar31);
                                    ppiVar18 = (int64_t **)*ppiVar33;
                                    if (ppiVar18 == (int64_t **)0x0) goto code_r0x000027a0;
                                }
                            }
                            goto code_r0x000027a0;
                        }
                        goto code_r0x00002a24;
                    }
                    uVar30 = sym.quotearg_style.constprop.0(pcVar38);
                    uVar32 = sym.imp.dcgettext(0, "cannot read directory %s", 5);
                    sym.imp.error(0, *(undefined4 *)(piVar16 + 8), uVar32, uVar30);
                    cVar48 = (code)0x0;
                    goto code_r0x00002b20;
                }
                piVar22 = (int32_t *)sym.imp.__errno_location();
                ppvVar49 = (void **)((uint64_t)ppvVar49 & 0xffffffff);
                if (*piVar22 != 0) {
                    uVar30 = sym.quotearg_n_style_colon.constprop.0(arg7_00, *(char **)(arg1 + 0x20));
                    uVar32 = sym.imp.dcgettext(0, "fts_read failed: %s", 5);
                    sym.imp.error(0, *piVar22, uVar32, uVar30);
                    var_1a1h = (code)0x0;
                }
                _data.000181d8 = 0;
                iVar9 = sym.rpl_fts_close(arg1);
                uVar30 = extraout_XMM0_Qa_06;
                if (iVar9 != 0) goto code_r0x000043ae;
                goto code_r0x000030ad;
            }
            if ((((*pcVar24 == '-') && (pcVar24[1] == '\0')) && (*pcVar38 == '-')) && (pcVar38[1] == '\0')) {
                uVar30 = sym.quotearg_style.constprop.0(pcVar38);
                uVar32 = sym.imp.dcgettext(0, "when reading file names from stdin, no file name of %s allowed", 5);
                uVar30 = sym.imp.error(0, 0, uVar32, uVar30);
                if (*pcVar38 != '\0') goto code_r0x00002de8;
            } else if (*pcVar38 != '\0') goto code_r0x0000263a;
            iVar12 = sym.imp.dcgettext(0, "invalid zero-length file name", 5);
            uVar30 = sym.quotearg_n_style_colon.constprop.0(iVar12, pcVar24);
            uVar30 = sym.imp.error(0, 0, "%s:%td: %s", uVar30);
code_r0x00002de8:
            uVar42 = 0;
        }
        iVar12 = sym.imp.getdelim(ptr + 2, ptr + 3, 0);
        if (-1 < iVar12) {
            ptr[1] = (void *)((int64_t)ptr[1] + 1);
            pcVar38 = (char *)ptr[2];
            uVar30 = extraout_XMM0_Qa_03;
            goto code_r0x00002601;
        }
        iVar9 = sym.imp.feof(*ptr);
        if (iVar9 == 0) {
            uVar11 = 0;
            pcVar24 = (char *)sym.quotearg_n_style_colon.constprop.0(arg7_01, filename);
            uVar30 = sym.imp.dcgettext(0, "%s: read error", 5);
            puVar15 = (undefined4 *)sym.imp.__errno_location();
            sym.imp.error(0, *puVar15, uVar30, pcVar24);
        }
code_r0x000030cd:
        uVar43 = (uint8_t)uVar11;
        sym.argv_iter_free(ptr);
        sym.di_set_free((int64_t)_data.00018220);
        if (_data.00018200 != (FILE *)0x0) {
            sym.di_set_free((int64_t)_data.00018200);
        }
        if ((filename != (char *)0x0) &&
           ((((**_reloc.stdin & 0x20) != 0 || (iVar9 = sym.rpl_fclose(*_reloc.stdin), iVar9 != 0)) && (uVar43 != 0)))) {
            piVar22 = (int32_t *)sym.quotearg_style.constprop.0(filename);
            uVar30 = sym.imp.dcgettext(0, "error reading %s", 5);
            if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) goto code_r0x0000254a;
            sym.imp.error(1, 0, uVar30, piVar22);
            ppvVar49 = ptr;
code_r0x000043ae:
            uVar30 = sym.imp.dcgettext(0, "fts_close failed", 5);
            uVar30 = sym.imp.error(0, *piVar22, uVar30);
            var_1a1h = (code)0x0;
code_r0x000030ad:
            uVar42 = (uint64_t)(uVar43 & (uint8_t)var_1a1h);
            goto code_r0x000025d4;
        }
        if (data.00018249 != (code)0x0) {
            pcVar24 = (char *)sym.imp.dcgettext(0, "total", 5);
            sym.print_size(0x181e0, pcVar24);
        }
        if (canary == *(int64_t *)(in_FS_OFFSET + 0x28)) {
            return uVar11 ^ 1;
        }
    }
code_r0x0000254a:
    // WARNING: Subroutine does not return
    sym.imp.__stack_chk_fail();
}



// sym.atexit
// WARNING: [rz-ghidra] Detected overlap for variable var_32h
// WARNING: [rz-ghidra] Detected overlap for variable var_31h

void sym.atexit(undefined8 param_1)
{
    // WARNING: Could not recover jumptable at 0x00001b74. Too many branches
    // WARNING: Treating indirect jump as call
    (*_reloc.__cxa_atexit)(param_1, 0, *(undefined8 *)0x17620);
    return;
}



