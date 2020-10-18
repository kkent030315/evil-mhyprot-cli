
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

//
// Pseudocode
//

undefined8 IOCTL_FUN_0001d6e0(undefined8 param_1,longlong param_2)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  ulonglong *puVar4;
  int iVar5;
  undefined8 uVar6;
  longlong lVar7;
  ulonglong uVar8;
  ulonglong *puVar9;
  ulonglong uVar10;
  uint local_res10 [2];
  ulonglong *local_res18;
  undefined8 local_198 [48];
  
  lVar7 = *(longlong *)(param_2 + 0xb8);
  puVar4 = *(ulonglong **)(param_2 + 0x18);
  uVar1 = *(uint *)(lVar7 + 0x18);
  uVar2 = *(uint *)(lVar7 + 0x10);
  uVar3 = *(uint *)(lVar7 + 8);
  uVar10 = (ulonglong)uVar3;
  *(undefined8 *)(param_2 + 0x38) = 0;
  if (uVar1 == 0x80104000) {
    uVar6 = FUN_000121ec((longlong)puVar4,uVar2);
    _DAT_0001a110 = (int)uVar6;
    *(uint *)puVar4 = -(uint)(_DAT_0001a110 != 0) & 1;
LAB_0001d75c:
    uVar10 = 4;
    goto LAB_0001da4f;
  }
  if (((uVar1 + 0x7feec000 & 0xfffcffff) == 0) && (uVar1 != 0x80134000)) goto LAB_0001da4f;
  if (uVar1 == 0x80134000) {
    lVar7 = FUN_00012314();
    *(int *)puVar4 = (int)lVar7;
    goto LAB_0001d75c;
  }
  if (uVar1 == 0x82054000) {
    uVar8 = FUN_000126d0(*(uint *)puVar4,(longlong)(uint *)((longlong)puVar4 + 4),
                         *(uint *)((longlong)puVar4 + 4));
    iVar5 = (int)uVar8;
  }
  else {
    if (uVar1 == 0x83024000) {
      uVar8 = FUN_000162ec((longlong)puVar4 + 4,(int *)puVar4);
      iVar5 = (int)uVar8;
    }
    else {
      if (uVar1 == 0x83074000) {
        uVar6 = FUN_00015f18();
        iVar5 = (int)uVar6;
      }
      else {
                    /* MHYPROT_IOCTL_READ_KERNEL_MEMORY */
        if (uVar1 != 0x83064000) {
          if (uVar1 == 0x82074000) {
            if (((uVar2 < 4) || (uVar3 < 0x38)) || (puVar4 == (ulonglong *)0x0)) goto LAB_0001da4f;
            puVar9 = (ulonglong *)ExAllocatePoolWithTag(1,uVar10,0x4746544d);
            *puVar9 = SUB168(ZEXT816(0xaaaaaaaaaaaaaaab) * ZEXT816(uVar10 - 8) >> 0x45,0) &
                      0xffffffff;
            uVar8 = FUN_000132b0((uint *)puVar4,puVar9);
            *(int *)(param_2 + 0x30) = (int)uVar8;
            if ((int)uVar8 < 0) {
              uVar10 = 8;
              *puVar4 = *puVar9;
            }
            else {
              uVar8 = *puVar9 * 0x30 + 8;
LAB_0001d842:
              *(ulonglong *)(param_2 + 0x38) = uVar8;
              FUN_000175c0(puVar4,puVar9,uVar8);
            }
LAB_0001d85b:
            uVar6 = 0x4746544d;
          }
          else {
            if (uVar1 == 0x82104000) {
              if (((uVar2 < 0x28) || (uVar3 < 0x20)) || (puVar4 == (ulonglong *)0x0))
              goto LAB_0001da4f;
              puVar9 = (ulonglong *)ExAllocatePoolWithTag(1,uVar10,0x4746544d);
              *(int *)puVar9 =
                   (int)SUB168(ZEXT816(0xaaaaaaaaaaaaaaab) * ZEXT816(uVar10 - 4) >> 0x44,0);
              uVar6 = FUN_0001377c((longlong)puVar4,(uint *)puVar9);
              *(int *)(param_2 + 0x30) = (int)uVar6;
              if (-1 < (int)uVar6) {
                uVar8 = (ulonglong)*(uint *)puVar9 * 0x18 + 4;
                goto LAB_0001d842;
              }
              uVar10 = 4;
              *(uint *)puVar4 = *(uint *)puVar9;
              goto LAB_0001d85b;
            }
            if (uVar1 == 0x82094000) {
              *(undefined4 *)puVar4 = 0;
              goto LAB_0001da4f;
            }
                    /* MHYPROT_IOCTL_INITIALIZE */
            if (uVar1 == 0x80034000) {
              if (uVar2 == 0x10) {
                puVar4[1] = puVar4[1] ^ 0xebbaaef4fff89042;
                *puVar4 = *puVar4 ^ puVar4[1];
                if (*(int *)((longlong)puVar4 + 4) == -0x45145114) {
                  FUN_000151a8(*(undefined4 *)puVar4);
                  if ((int)DAT_0001a108 == 0) {
                    FUN_0001301c((longlong *)&DAT_0001a0e8,puVar4[1]);
                    lVar7 = 7;
                    do {
                      uVar10 = FUN_00012eb0((uint **)&DAT_0001a0e8);
                      *puVar4 = uVar10;
                      DAT_0001a108._0_4_ = 1;
                      lVar7 = lVar7 + -1;
                    } while (lVar7 != 0);
                    uVar10 = 8;
                  }
                  else {
                    uVar10 = 0;
                  }
                }
              }
              goto LAB_0001da4f;
            }
            if (uVar1 == 0x81134000) goto LAB_0001da4f;
            if (uVar1 == 0x81144000) {
              uVar10 = FUN_00016654(*(uint *)puVar4,(longlong)local_198);
              iVar5 = (int)uVar10;
              if (-1 < iVar5) {
                uVar10 = (ulonglong)(uint)(iVar5 * 0x18);
                if (0 < iVar5) {
                  FUN_000175c0(puVar4,local_198,(longlong)iVar5 * 0x18);
                }
                goto LAB_0001da4f;
              }
              uVar10 = 4;
              goto LAB_0001d7c1;
            }
            local_res18 = (ulonglong *)0x0;
            local_res10[0] = 0;
            uVar8 = IOCTL_FUN_0001d000(uVar1,puVar4,uVar2,&local_res18,(int *)local_res10);
            puVar9 = local_res18;
            if ((char)uVar8 == '\0') goto LAB_0001da4f;
            if (uVar3 < local_res10[0]) {
              local_res10[0] = uVar3;
            }
            if ((local_res18 == (ulonglong *)0x0) || (local_res10[0] == 0)) goto LAB_0001da4f;
            uVar10 = (ulonglong)local_res10[0];
            FUN_000175c0(puVar4,local_res18,(ulonglong)local_res10[0]);
            uVar6 = 0;
          }
          ExFreePoolWithTag(puVar9,uVar6);
          goto LAB_0001da4f;
        }
        uVar6 = FUN_000163a8((undefined4 *)((longlong)puVar4 + 4),*puVar4,*(uint *)(puVar4 + 1));
        iVar5 = (int)uVar6;
      }
    }
  }
LAB_0001d7c1:
  *(int *)puVar4 = iVar5;
LAB_0001da4f:
  *(ulonglong *)(param_2 + 0x38) = uVar10;
  *(undefined4 *)(param_2 + 0x30) = 0;
  IofCompleteRequest(param_2,0);
  return 0;
}
