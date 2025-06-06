# JZLint - PQC

JZLint works together with [libcrux](https://github.com/cryspen/libcrux/)  
to perform certain lints for ML-KEM keys.

Communication between the two libraries is currently handled  
by exchanging JSON files in the form of requests and responses.  
In the `jzlint.properties` file, you can specify the following three properties:

1. **tmp.dir**  
   This property specifies the directory where the communication files  
   between libcrux and JZLint are written.  
   For example: `C:\tmp`

2. **executable.path**  
   This property specifies the path to the libcrux executable that will be called  
   by the Java-based JZLint library to perform linting.  
   For example: `C:\tmp\cli.exe`

3. **delete.files**  
   This property determines whether the exchanged files are deleted  
   after communication has ended.  
   Set to `false` if the files should be retained, `true` otherwise.

To ensure these properties are read correctly, the `jzlint.properties` file  
must be placed in the directory where JZLint is executed.


