#!/usr/bin/env bash
# Private input generation only. The operator owns subsequent SIM builds.
set -Eeuo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: prepare-inputs.sh MAIN_SOURCE TEACLAVE_CHECKOUT NEW_TASK_OUTPUT' >&2; exit 64; }
main_source=$(realpath -e -- "$1")
teaclave_checkout=$(realpath -e -- "$2")
[[ $3 == /* && ! -e $3 && ! -L $3 ]] || exit 64
helper_root=$(cd -- "$(dirname -- "$0")" && pwd)
# The profile manifest is the sole digest/path/mode owner. It hashes this
# script after authoring; this script reads those declarations without a cycle.
generation_owner=$(/usr/bin/python3 -I -B - "$main_source" "$helper_root" <<'OWNERS'
from pathlib import Path, PurePosixPath
import hashlib,json,re,sys
main,helper=map(Path,sys.argv[1:])
def unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('duplicate SDK generation declaration')
  result[key]=value
 return result
manifest_path=helper/'manifest.json'
if manifest_path.is_symlink() or not manifest_path.is_file():
 raise ValueError('SDK generation manifest is unavailable')
manifest=json.loads(manifest_path.read_text(),object_pairs_hook=unique)
if manifest['schema']!=1 or manifest['profile']!='fallible-allocation-v1':
 raise ValueError('SDK generation profile differs')
def verify(root,row):
 name=row['path'];relative=PurePosixPath(name)
 if (not name or relative.is_absolute() or relative.as_posix()!=name
     or '..' in relative.parts or '\\' in name):
  raise ValueError('invalid SDK generation owner path')
 expected=row['sha256'];mode=row['mode']
 if (not isinstance(expected,str) or re.fullmatch('[0-9a-f]{64}',expected) is None
     or type(mode) is not int or mode<0 or mode>0o777):
  raise ValueError('invalid SDK generation owner identity')
 path=root/name
 if (path.is_symlink() or not path.is_file() or path.resolve(strict=True)!=path
     or path.stat().st_mode&0o777!=mode):
  raise ValueError('SDK generation owner path/mode differs')
 if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
  raise ValueError('SDK generation owner bytes differ')
 return path
owner=verify(main,manifest['autotools_owner'])
for name in ('prepare-inputs.sh','approved-functions.sh'):
 rows=[row for row in manifest['build_inputs'] if row['path']==name]
 if len(rows)!=1:raise ValueError('SDK generation input declaration differs')
 verify(helper,rows[0])
print(owner)
OWNERS
)
readonly generation_owner
mkdir -- "$3"
BUILD_ROOT=$(realpath -e -- "$3")
BWRAP_BIN=/usr/bin/bwrap
SOURCE_DATE_EPOCH_VALUE=0
readonly BUILD_ROOT BWRAP_BIN SOURCE_DATE_EPOCH_VALUE
# shellcheck source=/dev/null
source "$helper_root/approved-functions.sh"
# Copy only tracked libunwind inputs, checking every actual compiler source
# against its original pinned blob or the two original approved patch hashes.
/usr/bin/python3 -I -B - "$teaclave_checkout" "$BUILD_ROOT" "$main_source" <<'COPY'
from pathlib import Path
import hashlib,json,os,subprocess,sys
checkout,out,main=map(Path,sys.argv[1:]);revision='2330b2a5aa8404d3c0a38e9d3a760144549f4943';prefix='sgx_unwind/libunwind/'
def git(*args):
 return subprocess.check_output(['/usr/bin/git','-C',str(checkout),*args],env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0'})
assert git('rev-parse','HEAD').decode().strip()==revision
assert git('rev-parse',revision+'^{tree}').decode().strip()=='e5497217494fb478ac5a3a6d0f15235254b14757'
patches={prefix+'src/mi/mempool.c':'623824d8f94eaa2a1a39de4a352f35f17417c89378891deef586a4be3fdaed70',prefix+'autogen.sh':'95acdcb3db07808dc65e6c7f31f492ff54a634099329c31407f4eafca38db3db'}
rows=[]
for entry in git('ls-tree','-rz',revision,'--',prefix).split(b'\0'):
 if not entry:continue
 metadata,path=entry.split(b'\t',1);mode,kind,oid=metadata.decode().split();path=path.decode();assert path.startswith(prefix) and '..' not in Path(path).parts
 assert kind=='blob' and mode in ('100644','100755'),(path,mode,kind)
 src=checkout/path;assert src.is_file() and not src.is_symlink(),path
 data=src.read_bytes();sha=hashlib.sha256(data).hexdigest()
 original=git('cat-file','blob',oid)
 if path in patches:
  assert data==original or sha==patches[path],path
  data=original
 else:assert data==original,path
 dst=out/'source'/path;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data);dst.chmod(0o700 if mode=='100755' else 0o600)
 rows.append({'path':path,'original_git_blob':oid,'git_mode':mode,'checkout_sha256':sha,'copied_sha256':hashlib.sha256(data).hexdigest()})
assert set(patches)<=set(row['path'] for row in rows)
# Apply the exact reviewed patches ONLY to our private source subtree.
patch_inputs={
 'teaclave-sgx-sdk-2330b2a-libunwind-get-pagesize.patch':'275a87899735a6a517a50c91a61a5feef67fe6eac70ebbb7bf8a2a2e0dc9f0a5',
 'teaclave-sgx-sdk-2330b2a-libunwind-autogen.patch':'1e4bc2618674e443383dec34516c8a8de40aa83adc7173ee7a39c6a50d684b8e',
}
patch_env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_CEILING_DIRECTORIES':str(out)}
for name,expected in patch_inputs.items():
 patch=main/'third_party/patches'/name
 assert patch.is_file() and not patch.is_symlink() and hashlib.sha256(patch.read_bytes()).hexdigest()==expected
 for options in [['--check'],[]]:
  subprocess.run(['/usr/bin/git','apply',*options,'--whitespace=error',str(patch)],cwd=out/'source',env=patch_env,check=True)
for path,expected in patches.items():assert hashlib.sha256((out/'source'/path).read_bytes()).hexdigest()==expected,path
(out/'approved-patches.json').write_text(json.dumps(patch_inputs,indent=2)+'\n')
(out/'source-inputs.json').write_text(json.dumps({'revision':revision,'scope':'tracked libunwind subtree only','files':rows},indent=2)+'\n')
COPY
# Source generation uses the ORIGINAL network-off NOCONFIGURE recipe and
# its original exact output inventory, undeclared-output and failure checks.
source_mirror=$BUILD_ROOT/source
unchanged=$(hash_source_without_autotools_outputs "$source_mirror")
write_autotools_data_evidence > "$BUILD_ROOT/autotools-data.tsv"
for tool in bash sh env bwrap autoreconf autoconf autoheader autom4te automake aclocal libtoolize m4 perl find sort sha256sum xargs stat grep sed cut dirname expr cp chmod mkdir rm git python3; do
  hash_binary "$tool" "/usr/bin/$tool"
done > "$BUILD_ROOT/generation-tools.tsv"
prepare_autotools_isolated "$source_mirror" "$unchanged"
negative_check_autotools_inventory "$source_mirror" "$unchanged"
negative_check_autogen_failure_propagation "$BUILD_ROOT" "$source_mirror"
validate_autotools_outputs "$source_mirror"
[[ $(hash_source_without_autotools_outputs "$source_mirror") == "$unchanged" ]]
full_tree=$(hash_tree "$source_mirror")
/usr/bin/python3 -I -B - "$BUILD_ROOT" "$helper_root" "$main_source" "$teaclave_checkout" "$unchanged" "$full_tree" "$generation_owner" <<'RECEIPT'
from pathlib import Path
import hashlib,json,os,sys
out,helper,main,checkout=map(Path,sys.argv[1:5]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=[]
for p in sorted((out/'source').rglob('*')):
 if p.is_file():files.append({'path':str(p.relative_to(out/'source')),'mode':oct(p.stat().st_mode&0o777),'sha256':sha(p)})
receipt={'schema':1,'scope':'task-owned pregenerated libunwind input only; no build/execution/stock-complete qualification','source_checkout':str(checkout),'mount_source':str(out/'source/sgx_unwind/libunwind'),'mount_destination':str(checkout/'sgx_unwind/libunwind'),'mount_required':'read-only private namespace only','required_build_env':{'HONEST_TEACLAVE_PREGENERATED_AUTOTOOLS':'1','SGX_MODE':'SIM'},'source_excluding_generated_sha256':sys.argv[5],'whole_input_tree_sha256':sys.argv[6],'files':files,'bindings':{str(p):sha(p) for p in [helper/'prepare-inputs.sh',helper/'approved-functions.sh',Path(sys.argv[7]),out/'source-inputs.json',out/'approved-patches.json',out/'autotools-data.tsv',out/'generation-tools.tsv']}}
(out/'input-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(out/'input-receipt.json')
RECEIPT
