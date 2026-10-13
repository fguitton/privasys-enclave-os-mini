# Verbatim bounded extraction from reviewed stock script; see manifest.
AUTOTOOLS_GENERATED_FILES=(
  INSTALL
  Makefile.in
  aclocal.m4
  autom4te.cache/output.0
  autom4te.cache/output.1
  autom4te.cache/output.2
  autom4te.cache/output.3
  autom4te.cache/requests
  autom4te.cache/traces.0
  autom4te.cache/traces.1
  autom4te.cache/traces.2
  autom4te.cache/traces.3
  config/ar-lib
  config/compile
  config/config.guess
  config/config.sub
  config/depcomp
  config/install-sh
  config/ltmain.sh
  config/missing
  configure
  include/config.h.in
  m4/libtool.m4
  m4/ltoptions.m4
  m4/ltsugar.m4
  m4/ltversion.m4
  'm4/lt~obsolete.m4'
  src/Makefile.in
)
AUTOTOOLS_GENERATED_DIRECTORIES=(autom4te.cache config m4)
readonly -a AUTOTOOLS_GENERATED_FILES AUTOTOOLS_GENERATED_DIRECTORIES

file_sha256() {
  local path=$1
  local digest_line digest
  [[ -f ${path} && ! -L ${path} ]] || return 65
  digest_line=$(sha256sum -- "${path}") || return 65
  digest=${digest_line%% *}
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || return 65
  printf '%s\n' "${digest}"
}

hash_evidence() {
  local producer=$1
  shift
  local evidence digest
  evidence=$(mktemp "${BUILD_ROOT}/hash-evidence.XXXXXX") || return 65
  if ! "${producer}" "$@" >"${evidence}"; then
    rm -f -- "${evidence}"
    return 65
  fi
  if ! digest=$(file_sha256 "${evidence}"); then
    rm -f -- "${evidence}"
    return 65
  fi
  rm -f -- "${evidence}" || return 65
  printf '%s\n' "${digest}"
}

write_tree_evidence() {
  local root=$1
  [[ -d ${root} && ! -L ${root} ]] || return 65
  (
    cd "${root}" || exit 65
    set -o pipefail
    find . -type f -printf 'mode=%m\tpath=%p\0' \
      | sort -z | sha256sum || exit 65
    find . -type f -print0 \
      | sort -z | xargs -0 -r sha256sum || exit 65
    find . -type l -printf 'link=%p\ttarget=%l\0' \
      | sort -z | sha256sum || exit 65
  )
}

hash_tree() {
  hash_evidence write_tree_evidence "$1"
}

write_autotools_data_evidence() {
  local label path resolved digest
  while IFS=$'\t' read -r label path; do
    resolved=$(realpath -e -- "${path}") || return 65
    [[ -d ${resolved} && ! -L ${resolved} ]] || return 65
    digest=$(hash_tree "${resolved}") || return 65
    printf '%s\t%s\n' "${label}" "${digest}" || return 65
  done <<'EOF'
autoconf-share	/usr/share/autoconf
automake-share	/usr/share/automake-1.18
automake-aclocal	/usr/share/aclocal-1.18
system-aclocal	/usr/share/aclocal
libtool-share	/usr/share/libtool
perl-share	/usr/share/perl/5.40
perl-arch	/usr/lib/x86_64-linux-gnu/perl/5.40
EOF
}

hash_binary() {
  local label=$1
  local path=$2
  local digest
  path=$(realpath -e -- "${path}") || return 65
  [[ -f ${path} && -x ${path} && ! -L ${path} ]] || return 65
  digest=$(file_sha256 "${path}") || return 65
  printf '%s\t%s\n' "${label}" "${digest}" || return 65
}

write_source_without_autotools_outputs_evidence() {
  local source_mirror=$1 generated unsupported
  local -a exclusions=()
  [[ -d ${source_mirror} && ! -L ${source_mirror} ]] || return 65
  for generated in "${AUTOTOOLS_GENERATED_FILES[@]}" \
      "${AUTOTOOLS_GENERATED_DIRECTORIES[@]}"; do
    exclusions+=(
      ! -path "./sgx_unwind/libunwind/${generated}"
    )
  done
  (
    cd "${source_mirror}" || exit 65
    set -o pipefail
    unsupported=$(find . -mindepth 1 "${exclusions[@]}" \
      ! -type f ! -type d ! -type l -print -quit) || exit 65
    [[ -z ${unsupported} ]] || exit 65
    find . -mindepth 1 -type d "${exclusions[@]}" \
      -printf 'directory\t%m\t%p\0' \
      | sort -z | sha256sum || exit 65
    find . -type f "${exclusions[@]}" -printf 'file\t%m\t%p\0' \
      | sort -z | sha256sum || exit 65
    find . -type f "${exclusions[@]}" -print0 \
      | sort -z | xargs -0 -r sha256sum || exit 65
    find . -type l "${exclusions[@]}" -printf 'link\t%m\t%p\t%l\0' \
      | sort -z | sha256sum || exit 65
  )
}

hash_source_without_autotools_outputs() {
  hash_evidence write_source_without_autotools_outputs_evidence "$1"
}

validate_autotools_outputs() {
  local source_mirror=$1
  local libunwind=${source_mirror}/sgx_unwind/libunwind
  local actual expected
  actual=$(
    cd "${libunwind}" || exit 69
    {
      for path in INSTALL Makefile.in aclocal.m4 configure \
          include/config.h.in src/Makefile.in; do
        [[ -f ${path} && ! -L ${path} ]] || exit 69
        printf 'f\t%s\t%s\n' "$(stat -c %a -- "${path}")" "${path}"
      done
      find autom4te.cache config m4 -mindepth 0 \
        -printf '%y\t%m\t%p\n'
    } | sort
  ) || return 69
  expected=$(sort <<'EOF'
d	700	autom4te.cache
d	700	config
d	700	m4
f	600	INSTALL
f	600	Makefile.in
f	600	aclocal.m4
f	600	autom4te.cache/output.0
f	600	autom4te.cache/output.1
f	600	autom4te.cache/output.2
f	600	autom4te.cache/output.3
f	600	autom4te.cache/requests
f	600	autom4te.cache/traces.0
f	600	autom4te.cache/traces.1
f	600	autom4te.cache/traces.2
f	600	autom4te.cache/traces.3
f	600	include/config.h.in
f	600	m4/libtool.m4
f	600	m4/ltoptions.m4
f	600	m4/ltsugar.m4
f	600	m4/ltversion.m4
f	600	m4/lt~obsolete.m4
f	600	src/Makefile.in
f	700	config/ar-lib
f	700	config/compile
f	700	config/config.guess
f	700	config/config.sub
f	700	config/depcomp
f	700	config/install-sh
f	700	config/ltmain.sh
f	700	config/missing
f	700	configure
EOF
  ) || return 69
  [[ ${actual} == "${expected}" ]] || {
    echo 'Teaclave SGX-SIM pregenerated Autotools inventory is unexpected' >&2
    return 69
  }
  [[ $(grep -Fc '__x86_return_thunk()' "${libunwind}/configure") -eq 2 ]] || {
    echo 'Teaclave SGX-SIM pregenerated configure thunk injection is unexpected' >&2
    return 69
  }
}

prepare_autotools_isolated() {
  local source_mirror=$1
  local unchanged_source_sha256=$2
  local canonical=/tmp/honest-autotools/source
  "${BWRAP_BIN}" \
    --clearenv \
    --unshare-all \
    --die-with-parent \
    --new-session \
    --cap-drop ALL \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --symlink usr/sbin /sbin \
    --ro-bind /etc /etc \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --dir /tmp/honest-autotools \
    --bind "${source_mirror}" "${canonical}" \
    --setenv PATH /usr/bin:/bin \
    --setenv HOME /nonexistent \
    --setenv LC_ALL C.UTF-8 \
    --setenv TZ UTC \
    --setenv SOURCE_DATE_EPOCH "${SOURCE_DATE_EPOCH_VALUE}" \
    --setenv NOCONFIGURE 1 \
    --chdir "${canonical}/sgx_unwind/libunwind" \
    /bin/sh ./autogen.sh || return 69
  prepare_autotools_isolated_validation \
    "${source_mirror}" "${unchanged_source_sha256}"
}

prepare_autotools_isolated_validation() {
  local source_mirror=$1
  local unchanged_source_sha256=$2
  validate_autotools_outputs "${source_mirror}" || return 69
  [[ $(hash_source_without_autotools_outputs "${source_mirror}") \
      == "${unchanged_source_sha256}" ]] || {
    echo 'Teaclave SGX-SIM Autotools generation changed an undeclared source path' >&2
    return 69
  }
}

negative_check_autotools_inventory() {
  local source_mirror=$1
  local unchanged_source_sha256=$2
  local sentinel=${source_mirror}/sgx_unwind/libunwind/configure~
  local output status
  [[ ! -e ${sentinel} && ! -L ${sentinel} ]] || return 69
  printf 'unexpected generated output\n' >"${sentinel}" || return 69
  set +e
  output=$(prepare_autotools_isolated_validation \
    "${source_mirror}" "${unchanged_source_sha256}" 2>&1)
  status=$?
  set -e
  rm -f -- "${sentinel}" || return 69
  [[ ${status} -eq 69 \
    && ${output} == *'changed an undeclared source path'* ]] || {
    echo 'Teaclave SGX-SIM Autotools unexpected-output sentinel was not rejected' >&2
    return 1
  }
  prepare_autotools_isolated_validation \
    "${source_mirror}" "${unchanged_source_sha256}"
}

negative_check_autogen_failure_propagation() {
  local physical_root=$1
  local source_mirror=$2
  local fixture=${physical_root}/autogen-failure-negative
  local fixture_source=${fixture}/source
  local fixture_output=${fixture}/output
  local missing_source=${fixture}/missing-source
  local config_before config_after output status missing_status
  mkdir -p "${fixture_source}/include" "${fixture_output}/include" \
    "${missing_source}" || return 69
  cp -- "${source_mirror}/sgx_unwind/libunwind/autogen.sh" \
    "${fixture_source}/autogen.sh" || return 69
  cp -- "${source_mirror}/sgx_unwind/libunwind/autogen.sh" \
    "${missing_source}/autogen.sh" || return 69
  cat >"${fixture_source}/configure" <<'EOF'
#!/bin/sh
# __x86_return_thunk()
# __x86_return_thunk()
exit 42
EOF
  chmod 0700 "${fixture_source}/configure" || return 69
  printf '#define HAVE_MINCORE 1\n' >"${fixture_output}/include/config.h" || return 69
  config_before=$(file_sha256 "${fixture_output}/include/config.h") || return 69
  set +e
  output=$(
    cd "${fixture_output}" || exit 69
    /usr/bin/env -i \
      PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C.UTF-8 TZ=UTC \
      SOURCE_DATE_EPOCH=0 HONEST_TEACLAVE_PREGENERATED_AUTOTOOLS=1 \
      CFLAGS= /bin/sh "${fixture_source}/autogen.sh" 2>&1
  )
  status=$?
  /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C.UTF-8 TZ=UTC \
    HONEST_TEACLAVE_PREGENERATED_AUTOTOOLS=1 CFLAGS= \
    /bin/sh "${missing_source}/autogen.sh" >/dev/null 2>&1
  missing_status=$?
  set -e
  config_after=$(file_sha256 "${fixture_output}/include/config.h") || return 69
  [[ ${status} -eq 42 \
    && ${output} == '__x86_return_thunk() already exist...' \
    && ${missing_status} -eq 1 \
    && ${config_after} == "${config_before}" ]] || {
    echo 'Teaclave SGX-SIM Autotools configure failure was not preserved' >&2
    return 1
  }
  find "${fixture}" -depth -delete || return 69
}
