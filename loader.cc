#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <string>
#include <vector>

#include <bfd.h>

#include "log.h"
#include "options.h"
#include "loader.h"


const char *binary_types_descr[][2] = {
  {"auto", "Try to automatically determine binary format (default)"},
  {"raw" , "Raw binary (memory dump, ROM, network capture, ...)"},
  {"elf" , "Unix ELF"},
  {"pe"  , "Windows PE"},
  {NULL  , NULL}
};

const char *binary_arch_descr[][2] = {
  {"auto"    , "Try to automatically determine architecture (default)"},
  {"aarch64" , "aarch64 (experimental)"},
  {"arm"     , "arm (experimental)"},
  {"mips"    , "mips (experimental)"},
  {"ppc"     , "ppc: Specify ppc-32 or ppc-64 (default ppc-64, experimental)"},
  {"x86"     , "x86: Specify x86-16, x86-32 or x86-64 (default x86-64)"},
  {NULL      , NULL}
};


static bfd*
open_bfd(std::string &fname)
{
  static int bfd_inited = 0;

  bfd *bin;

  if(!bfd_inited) {
    bfd_init();
    bfd_inited = 1;
  }

  bin = bfd_openr(fname.c_str(), NULL);
  if(!bin) {
    print_err("failed to open binary '%s' (%s)", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  if(!bfd_check_format(bin, bfd_object)) {
    print_err("file '%s' does not look like a binary object (%s), maybe load as raw?", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  /* Some versions of bfd_check_format pessimistically set a wrong_format
   * error before detecting the format, and then neglect to unset it once
   * the format has been detected. We unset it manually to prevent problems. */
  bfd_set_error(bfd_error_no_error);

  if(bfd_get_flavour(bin) == bfd_target_unknown_flavour) {
    print_err("unrecognized format for binary '%s' (%s)", fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  verbose(2, "binary '%s' has format '%s'", fname.c_str(), bin->xvec->name);

  return bin;
}


int
load_symbols_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_symtab;
  Symbol *sym;

  bfd_symtab = NULL;

  n = bfd_get_symtab_upper_bound(bfd_h);
  if(n < 0) {
    print_err("failed to read symtab (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_symtab = (asymbol**)malloc(n);
    if(!bfd_symtab) {
      print_err("out of memory");
      goto fail;
    }
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if(nsyms < 0) {
      print_err("failed to read symtab (%s)", bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      if(bfd_symtab[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type |= Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_symtab[i]->name);
        sym->addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_symtab) free(bfd_symtab);

  return ret;
}


int
load_dynsym_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_dynsym;
  Symbol *sym;

  bfd_dynsym = NULL;

  n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if(n < 0) {
    print_err("failed to read dynamic symtab (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_dynsym = (asymbol**)malloc(n);
    if(!bfd_dynsym) {
      print_err("out of memory");
      goto fail;
    }
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if(nsyms < 0) {
      print_err("failed to read dynamic symtab (%s)", bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      if(bfd_dynsym[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type |= Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_dynsym[i]->name);
        sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_dynsym) free(bfd_dynsym);

  return ret;
}


int
load_dynrelocs_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long nsyms, nrels, relsize, i;
  unsigned int symsize;
  asymbol **bfd_symtab = nullptr;
  arelent **bfd_relocs = nullptr;
  reloc_howto_type *bfd_howto;

  bfd_symtab = nullptr;
  bfd_relocs = nullptr;
  relsize = bfd_get_dynamic_reloc_upper_bound(bfd_h);
  if(relsize == 0) {
    return 0;
  }
  if(relsize < 0) {
    print_err("failed to read dynamic relocations size (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  }
  nsyms = bfd_read_minisymbols(bfd_h, TRUE, (void**)&bfd_symtab, &symsize);
  if(nsyms < 0) {
    print_err("failed to read symtab (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  }

  bfd_relocs = (arelent**)malloc(relsize);
  nrels = bfd_canonicalize_dynamic_reloc(bfd_h, bfd_relocs, bfd_symtab);
  if(nrels < 0) {
    print_err("failed to read dynamic relocations (%s)", bfd_errmsg(bfd_get_error()));
    goto fail;
  }
  /* Apply relocations */
  for(i = 0; i < nrels; i++) {
    arelent *bfd_reloc = bfd_relocs[i];
    asymbol *bfd_symbol = *(bfd_reloc->sym_ptr_ptr);
    bfd_howto = bfd_reloc->howto;

    for(const auto& sec : bin->sections) {
      /* Apply relocation to data of any executable section within range */
      size_t bytesize = (bfd_howto->bitsize / 8);
      if(bfd_reloc->address < sec.vma ||
         bfd_reloc->address > sec.vma + sec.size - bytesize ||
         sec.type != Section::SEC_TYPE_CODE) {
        continue;
      }
      /* Compute relocation value */
      bfd_vma relocation = 0;
      if(bfd_is_com_section(bfd_symbol->section)) {
        relocation = bfd_symbol->value;
      }
      relocation += bfd_reloc->addend;
      relocation >>= (bfd_vma)bfd_howto->rightshift;
      relocation <<= (bfd_vma)bfd_howto->bitpos;

      /* Patch data */
#define APPLY_RELOC(x) \
  ((x & ~bfd_howto->dst_mask) | (((x & bfd_howto->src_mask) + relocation) & bfd_howto->dst_mask))

      bfd_vma data_offset = bfd_reloc->address * bfd_octets_per_byte(bfd_h);
      bfd_byte* data = sec.bytes + (data_offset - sec.vma);

      switch (bfd_howto->size) {
      case 0: bfd_put_8 (bfd_h, APPLY_RELOC(bfd_get_8 (bfd_h, data)), data); break;
      case 1: bfd_put_16(bfd_h, APPLY_RELOC(bfd_get_16(bfd_h, data)), data); break;
      case 2: bfd_put_32(bfd_h, APPLY_RELOC(bfd_get_32(bfd_h, data)), data); break;
      case 4: bfd_put_64(bfd_h, APPLY_RELOC(bfd_get_64(bfd_h, data)), data); break;
      default:
        print_err("unsupported relocation size (%d)", bfd_howto->size);
        goto fail;
      }
#undef APPLY_RELOC
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_symtab) free(bfd_symtab);
  if(bfd_relocs) free(bfd_relocs);

  return ret;
}


int
load_sections_bfd(bfd *bfd_h, Binary *bin)
{
  int bfd_flags, sectype;
  uint64_t vma, size;
  const char *secname;
  asection* bfd_sec;
  Section *sec;

  for(bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

    sectype = Section::SEC_TYPE_NONE;
    if(bfd_flags & SEC_CODE) {
      sectype |= Section::SEC_TYPE_CODE;
    } else if(bfd_flags & SEC_DATA) {
      sectype |= Section::SEC_TYPE_DATA;
    } else {
      continue;
    }

    vma     = bfd_section_vma(bfd_h, bfd_sec);
    size    = bfd_section_size(bfd_h, bfd_sec);
    secname = bfd_section_name(bfd_h, bfd_sec);
    if(!secname) secname = "<unnamed>";

    bin->sections.push_back(Section());
    sec = &bin->sections.back();

    sec->binary = bin;
    sec->name   = std::string(secname);
    sec->type   = sectype;
    sec->vma    = vma;
    sec->size   = size;
    sec->bytes  = (uint8_t*)malloc(size);
    if(!sec->bytes) {
      print_err("out of memory");
      return -1;
    }

    if(!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
      print_err("failed to read section '%s' (%s)", secname, bfd_errmsg(bfd_get_error()));
      return -1;
    }
  }

  return 0;
}


int
load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  bfd_h = NULL;

  bfd_h = open_bfd(fname);
  if(!bfd_h) {
    goto fail;
  }

  bin->filename = std::string(fname);
  bin->entry    = bfd_get_start_address(bfd_h);

  bin->type_str = std::string(bfd_h->xvec->name);
  switch(bfd_h->xvec->flavour) {
  case bfd_target_elf_flavour:
    bin->type = Binary::BIN_TYPE_ELF;
    break;
  case bfd_target_coff_flavour:
    bin->type = Binary::BIN_TYPE_PE;
    break;
  case bfd_target_unknown_flavour:
  default:
    print_err("unsupported binary type (%s)", bfd_h->xvec->name);
    goto fail;
  }

  bfd_info = bfd_get_arch_info(bfd_h);
  bin->arch_str = std::string(bfd_info->printable_name);
  switch(bfd_info->arch) {
  case bfd_arch_i386:
    switch(bfd_info->mach) {
    case bfd_mach_i386_i386:
      bin->arch = Binary::ARCH_X86;
      bin->bits = 32;
      break;
    case bfd_mach_x86_64:
      bin->arch = Binary::ARCH_X86;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_arm:
    switch(bfd_info->mach) {
    case bfd_mach_arm_5T:
      bin->arch = Binary::ARCH_ARM;
      bin->bits = 32;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_aarch64:
    switch(bfd_info->mach) {
    case bfd_mach_aarch64:
    case bfd_mach_aarch64_ilp32:
      bin->arch = Binary::ARCH_AARCH64;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_mips:
    switch(bfd_info->mach) {
    case bfd_mach_mips16:
      bin->arch = Binary::ARCH_MIPS;
      bin->bits = 16;
      break;
    case bfd_mach_mipsisa32r2:
      bin->arch = Binary::ARCH_MIPS;
      bin->bits = 32;
      break;
    case bfd_mach_mipsisa64:
      bin->arch = Binary::ARCH_MIPS;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  case bfd_arch_powerpc:
    switch(bfd_info->mach) {
    case bfd_mach_ppc:
      bin->arch = Binary::ARCH_PPC;
      bin->bits = 32;
      break;
    case bfd_mach_ppc64:
      bin->arch = Binary::ARCH_PPC;
      bin->bits = 64;
      break;
    default:
      goto fail_arch;
    }
    break;

  default:
fail_arch:
    print_err("unsupported architecture (%s, [%u, %u])", bfd_info->printable_name, bfd_info->arch, bfd_info->mach);
    goto fail;
  }

  /* Symbol handling is best-effort only (they may not even be present) */
  load_symbols_bfd(bfd_h, bin);
  load_dynsym_bfd(bfd_h, bin);

  if(load_sections_bfd(bfd_h, bin) < 0) goto fail;

  /* Apply relocations if necessary */
  if (bin->arch == Binary::ARCH_PPC) {
    load_dynrelocs_bfd(bfd_h, bin);
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_h) bfd_close(bfd_h);

  return ret;
}


int
load_binary_raw(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  int ret;
  long fsize;
  FILE *f;
  Section *sec;

  f = NULL;

  bin->filename = std::string(fname);
  bin->type     = type;
  bin->type_str = std::string("raw");

  if(options.binary.arch == Binary::ARCH_NONE) {
    print_err("cannot determine binary architecture, specify manually");
    goto fail;
  }
  bin->arch     = options.binary.arch;
  bin->bits     = options.binary.bits;
  bin->arch_str = std::string(binary_arch_descr[(int)options.binary.arch][0]);
  bin->entry    = 0;

  if(!bin->bits) {
    switch(bin->arch) {
    case Binary::ARCH_X86:
      bin->bits = 64;
      break;
    default:
      break;
    }
  }

  bin->sections.push_back(Section());
  sec = &bin->sections.back();

  sec->binary = bin;
  sec->name   = std::string("raw");
  sec->type   = Section::SEC_TYPE_CODE;
  sec->vma    = options.binary.base_vma;

  f = fopen(fname.c_str(), "rb");
  if(!f) {
    print_err("failed to open binary '%s' (%s)", fname.c_str(), strerror(errno));
    goto fail;
  }

  fseek(f, 0L, SEEK_END);
  fsize = ftell(f);
  if(fsize <= 0) {
    print_err("binary '%s' appears to be empty", fname.c_str());
    goto fail;
  }

  sec->size  = (uint64_t)fsize;
  sec->bytes = (uint8_t*)malloc(fsize);
  if(!sec->bytes) {
    print_err("out of memory");
    goto fail;
  }

  fseek(f, 0L, SEEK_SET);
  if(fread(sec->bytes, 1, fsize, f) != (size_t)fsize) {
    print_err("failed to read binary '%s'", fname.c_str());
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(f) {
    fclose(f);
  }

  return ret;
}


int
load_binary(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  if(type == Binary::BIN_TYPE_RAW) {
    return load_binary_raw(fname, bin, type);
  } else {
    return load_binary_bfd(fname, bin, type);
  }
}


void
unload_binary(Binary *bin)
{
  size_t i;
  Section *sec;

  for(i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if(sec->bytes) {
      free(sec->bytes);
    }
  }
}
