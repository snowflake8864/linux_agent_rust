1. 参照/opt/offline_responds/getdirpolicy.json 来添加防篡改

{"code":"000000","data":[{"id":0,"dir":"/root/test","type":1,"hash":"","protect_rw":15,"include_file":"asp|jsp|php|db","protect_file":"","protect_folder":"","is_extend":1,"process":[]},{"id":0,"dir":"/root/abc","type":1,"hash":"","protect_rw":9,"include_file":"","protect_file":"txt|out","protect_folder":"/root/abc/123","is_extend":1,"process":[{"hash":"a352bd1aeb9a87988c0658ac249a0a67"},{"hash":"60e5cdb5a76d5283049623e7cb02f4fc"}]}],"msg":"OK"}

dir ：受保护的目录或文件
type：1--目录， 
hash:

protect_rw: 保护方式， 1--读取；2--写入；4--删除；8--重命名；16--新建,各个方式可以位与
include_file：保护目录下文件的类型后缀，为空是所有文件类型（与protect_file互斥）
protect_file： 保护目录下 排除的文件类型的后缀（与include_file互斥）
protect_folder：只有当is_extend 为1时才有作用，排除的子目录(不受保护)
process：信任进程，里面用hash表示一个进程，可以有多个，参考上面例子;可以为空，表示没有信任进程

