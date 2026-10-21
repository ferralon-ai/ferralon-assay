package depreach

// platformType is a platformMethods entry: the type's direct supertypes other than
// java/lang/Object, and the methods it declares that a class-path class can override,
// each as its name and parameter descriptor ("add(ILjava/lang/Object;)"), space-separated.
type platformType struct{ supers, methods string }

// platformMethodsJDK is the feature release platformMethods was generated from, the only
// runtime it describes.
const platformMethodsJDK = 21

// platformMethods lists every java.base type a class-path class can extend or implement,
// and every supertype of one, with the methods each declares that a class-path class can
// override: what the JDK can name on an object it holds under that type (jdkCallable).
// java/lang/Object is left out; objectOverridable has its methods. A platform type not
// listed here (any other module's, or a later JDK's) has unknown methods, and so has every
// type when the runtime is not known to be platformMethodsJDK (Classpath.JDK).
//
// Generated from the java.base classes of Temurin 21.0.12.1+1 (macOS aarch64), extracted
// from lib/modules with jimage, reading only access flags, super_class, interfaces, the
// methods' names, descriptors and flags, and the PermittedSubclasses attribute. A type is
// a root of the list when it is public, not final, has no PermittedSubclasses and sits in
// a package java.base exports unqualified (java --describe-module java.base); the list is
// the roots plus the transitive closure of their supertypes (1100 types). A method is kept
// when it is public or protected and neither static, final, private, <init> nor <clinit>:
// a class-path class is in another runtime package, so it cannot override a
// package-private method (JVMS §5.4.5). The key drops the return type so that a covariant
// override matches the method it overrides.
var platformMethods = map[string]platformType{
	"java/io/BufferedInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "available() close() mark(I) markSupported() read() read([BII) reset() skip(J) transferTo(Ljava/io/OutputStream;)",
	},
	"java/io/BufferedOutputStream": {
		supers:  "java/io/FilterOutputStream",
		methods: "flush() write(I) write([BII)",
	},
	"java/io/BufferedReader": {
		supers:  "java/io/Reader",
		methods: "close() lines() mark(I) markSupported() read() read([CII) readLine() ready() reset() skip(J)",
	},
	"java/io/BufferedWriter": {
		supers:  "java/io/Writer",
		methods: "close() flush() newLine() write(I) write(Ljava/lang/String;II) write([CII)",
	},
	"java/io/ByteArrayInputStream": {
		supers:  "java/io/InputStream",
		methods: "available() close() mark(I) markSupported() read() read([BII) readAllBytes() readNBytes([BII) reset() skip(J) transferTo(Ljava/io/OutputStream;)",
	},
	"java/io/ByteArrayOutputStream": {
		supers:  "java/io/OutputStream",
		methods: "close() reset() size() toByteArray() toString() toString(I) toString(Ljava/lang/String;) toString(Ljava/nio/charset/Charset;) write(I) write([BII) writeBytes([B) writeTo(Ljava/io/OutputStream;)",
	},
	"java/io/CharArrayReader": {
		supers:  "java/io/Reader",
		methods: "close() mark(I) markSupported() read() read(Ljava/nio/CharBuffer;) read([CII) ready() reset() skip(J)",
	},
	"java/io/CharArrayWriter": {
		supers:  "java/io/Writer",
		methods: "append(C) append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II) close() flush() reset() size() toCharArray() toString() write(I) write(Ljava/lang/String;II) write([CII) writeTo(Ljava/io/Writer;)",
	},
	"java/io/CharConversionException": {
		supers: "java/io/IOException",
	},
	"java/io/Closeable": {
		supers:  "java/lang/AutoCloseable",
		methods: "close()",
	},
	"java/io/DataInput": {
		methods: "readBoolean() readByte() readChar() readDouble() readFloat() readFully([B) readFully([BII) readInt() readLine() readLong() readShort() readUTF() readUnsignedByte() readUnsignedShort() skipBytes(I)",
	},
	"java/io/DataInputStream": {
		supers: "java/io/FilterInputStream java/io/DataInput",
	},
	"java/io/DataOutput": {
		methods: "write(I) write([B) write([BII) writeBoolean(Z) writeByte(I) writeBytes(Ljava/lang/String;) writeChar(I) writeChars(Ljava/lang/String;) writeDouble(D) writeFloat(F) writeInt(I) writeLong(J) writeShort(I) writeUTF(Ljava/lang/String;)",
	},
	"java/io/DataOutputStream": {
		supers:  "java/io/FilterOutputStream java/io/DataOutput",
		methods: "flush() write(I) write([BII)",
	},
	"java/io/EOFException": {
		supers: "java/io/IOException",
	},
	"java/io/Externalizable": {
		supers:  "java/io/Serializable",
		methods: "readExternal(Ljava/io/ObjectInput;) writeExternal(Ljava/io/ObjectOutput;)",
	},
	"java/io/File": {
		supers:  "java/io/Serializable java/lang/Comparable",
		methods: "canExecute() canRead() canWrite() compareTo(Ljava/io/File;) compareTo(Ljava/lang/Object;) createNewFile() delete() deleteOnExit() equals(Ljava/lang/Object;) exists() getAbsoluteFile() getAbsolutePath() getCanonicalFile() getCanonicalPath() getFreeSpace() getName() getParent() getParentFile() getPath() getTotalSpace() getUsableSpace() hashCode() isAbsolute() isDirectory() isFile() isHidden() lastModified() length() list() list(Ljava/io/FilenameFilter;) listFiles() listFiles(Ljava/io/FileFilter;) listFiles(Ljava/io/FilenameFilter;) mkdir() mkdirs() renameTo(Ljava/io/File;) setExecutable(Z) setExecutable(ZZ) setLastModified(J) setReadOnly() setReadable(Z) setReadable(ZZ) setWritable(Z) setWritable(ZZ) toPath() toString() toURI() toURL()",
	},
	"java/io/FileFilter": {
		methods: "accept(Ljava/io/File;)",
	},
	"java/io/FileInputStream": {
		supers:  "java/io/InputStream",
		methods: "available() close() getChannel() read() read([B) read([BII) readAllBytes() readNBytes(I) skip(J) transferTo(Ljava/io/OutputStream;)",
	},
	"java/io/FileNotFoundException": {
		supers: "java/io/IOException",
	},
	"java/io/FileOutputStream": {
		supers:  "java/io/OutputStream",
		methods: "close() getChannel() write(I) write([B) write([BII)",
	},
	"java/io/FileReader": {
		supers: "java/io/InputStreamReader",
	},
	"java/io/FileWriter": {
		supers: "java/io/OutputStreamWriter",
	},
	"java/io/FilenameFilter": {
		methods: "accept(Ljava/io/File;Ljava/lang/String;)",
	},
	"java/io/FilterInputStream": {
		supers:  "java/io/InputStream",
		methods: "available() close() mark(I) markSupported() read() read([B) read([BII) reset() skip(J)",
	},
	"java/io/FilterOutputStream": {
		supers:  "java/io/OutputStream",
		methods: "close() flush() write(I) write([B) write([BII)",
	},
	"java/io/FilterReader": {
		supers:  "java/io/Reader",
		methods: "close() mark(I) markSupported() read() read([CII) ready() reset() skip(J)",
	},
	"java/io/FilterWriter": {
		supers:  "java/io/Writer",
		methods: "close() flush() write(I) write(Ljava/lang/String;II) write([CII)",
	},
	"java/io/Flushable": {
		methods: "flush()",
	},
	"java/io/IOError": {
		supers: "java/lang/Error",
	},
	"java/io/IOException": {
		supers: "java/lang/Exception",
	},
	"java/io/InputStream": {
		supers:  "java/io/Closeable",
		methods: "available() close() mark(I) markSupported() read() read([B) read([BII) readAllBytes() readNBytes(I) readNBytes([BII) reset() skip(J) skipNBytes(J) transferTo(Ljava/io/OutputStream;)",
	},
	"java/io/InputStreamReader": {
		supers:  "java/io/Reader",
		methods: "close() getEncoding() read() read(Ljava/nio/CharBuffer;) read([CII) ready()",
	},
	"java/io/InterruptedIOException": {
		supers: "java/io/IOException",
	},
	"java/io/InvalidClassException": {
		supers:  "java/io/ObjectStreamException",
		methods: "getMessage()",
	},
	"java/io/InvalidObjectException": {
		supers: "java/io/ObjectStreamException",
	},
	"java/io/LineNumberInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "available() getLineNumber() mark(I) read() read([BII) reset() setLineNumber(I) skip(J)",
	},
	"java/io/LineNumberReader": {
		supers:  "java/io/BufferedReader",
		methods: "getLineNumber() mark(I) read() read([CII) readLine() reset() setLineNumber(I) skip(J)",
	},
	"java/io/NotActiveException": {
		supers: "java/io/ObjectStreamException",
	},
	"java/io/NotSerializableException": {
		supers: "java/io/ObjectStreamException",
	},
	"java/io/ObjectInput": {
		supers:  "java/io/DataInput java/lang/AutoCloseable",
		methods: "available() close() read() read([B) read([BII) readObject() skip(J)",
	},
	"java/io/ObjectInputFilter": {
		methods: "checkInput(Ljava/io/ObjectInputFilter$FilterInfo;)",
	},
	"java/io/ObjectInputFilter$FilterInfo": {
		methods: "arrayLength() depth() references() serialClass() streamBytes()",
	},
	"java/io/ObjectInputStream": {
		supers:  "java/io/InputStream java/io/ObjectInput java/io/ObjectStreamConstants",
		methods: "available() close() defaultReadObject() enableResolveObject(Z) read() read([BII) readBoolean() readByte() readChar() readClassDescriptor() readDouble() readFields() readFloat() readFully([B) readFully([BII) readInt() readLine() readLong() readObjectOverride() readShort() readStreamHeader() readUTF() readUnshared() readUnsignedByte() readUnsignedShort() registerValidation(Ljava/io/ObjectInputValidation;I) resolveClass(Ljava/io/ObjectStreamClass;) resolveObject(Ljava/lang/Object;) resolveProxyClass([Ljava/lang/String;) skipBytes(I)",
	},
	"java/io/ObjectInputStream$GetField": {
		methods: "defaulted(Ljava/lang/String;) get(Ljava/lang/String;B) get(Ljava/lang/String;C) get(Ljava/lang/String;D) get(Ljava/lang/String;F) get(Ljava/lang/String;I) get(Ljava/lang/String;J) get(Ljava/lang/String;Ljava/lang/Object;) get(Ljava/lang/String;S) get(Ljava/lang/String;Z) getObjectStreamClass()",
	},
	"java/io/ObjectInputValidation": {
		methods: "validateObject()",
	},
	"java/io/ObjectOutput": {
		supers:  "java/io/DataOutput java/lang/AutoCloseable",
		methods: "close() flush() write(I) write([B) write([BII) writeObject(Ljava/lang/Object;)",
	},
	"java/io/ObjectOutputStream": {
		supers:  "java/io/OutputStream java/io/ObjectOutput java/io/ObjectStreamConstants",
		methods: "annotateClass(Ljava/lang/Class;) annotateProxyClass(Ljava/lang/Class;) close() defaultWriteObject() drain() enableReplaceObject(Z) flush() putFields() replaceObject(Ljava/lang/Object;) reset() useProtocolVersion(I) write(I) write([B) write([BII) writeBoolean(Z) writeByte(I) writeBytes(Ljava/lang/String;) writeChar(I) writeChars(Ljava/lang/String;) writeClassDescriptor(Ljava/io/ObjectStreamClass;) writeDouble(D) writeFields() writeFloat(F) writeInt(I) writeLong(J) writeObjectOverride(Ljava/lang/Object;) writeShort(I) writeStreamHeader() writeUTF(Ljava/lang/String;) writeUnshared(Ljava/lang/Object;)",
	},
	"java/io/ObjectOutputStream$PutField": {
		methods: "put(Ljava/lang/String;B) put(Ljava/lang/String;C) put(Ljava/lang/String;D) put(Ljava/lang/String;F) put(Ljava/lang/String;I) put(Ljava/lang/String;J) put(Ljava/lang/String;Ljava/lang/Object;) put(Ljava/lang/String;S) put(Ljava/lang/String;Z) write(Ljava/io/ObjectOutput;)",
	},
	"java/io/ObjectStreamConstants": {},
	"java/io/ObjectStreamException": {
		supers: "java/io/IOException",
	},
	"java/io/ObjectStreamField": {
		supers:  "java/lang/Comparable",
		methods: "compareTo(Ljava/lang/Object;) getName() getOffset() getType() getTypeCode() getTypeString() isPrimitive() isUnshared() setOffset(I) toString()",
	},
	"java/io/OptionalDataException": {
		supers: "java/io/ObjectStreamException",
	},
	"java/io/OutputStream": {
		supers:  "java/io/Closeable java/io/Flushable",
		methods: "close() flush() write(I) write([B) write([BII)",
	},
	"java/io/OutputStreamWriter": {
		supers:  "java/io/Writer",
		methods: "append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II) close() flush() getEncoding() write(I) write(Ljava/lang/String;II) write([CII)",
	},
	"java/io/PipedInputStream": {
		supers:  "java/io/InputStream",
		methods: "available() close() connect(Ljava/io/PipedOutputStream;) read() read([BII) receive(I)",
	},
	"java/io/PipedOutputStream": {
		supers:  "java/io/OutputStream",
		methods: "close() connect(Ljava/io/PipedInputStream;) flush() write(I) write([BII)",
	},
	"java/io/PipedReader": {
		supers:  "java/io/Reader",
		methods: "close() connect(Ljava/io/PipedWriter;) read() read([CII) ready()",
	},
	"java/io/PipedWriter": {
		supers:  "java/io/Writer",
		methods: "close() connect(Ljava/io/PipedReader;) flush() write(I) write([CII)",
	},
	"java/io/PrintStream": {
		supers:  "java/io/FilterOutputStream java/lang/Appendable java/io/Closeable",
		methods: "append(C) append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II) charset() checkError() clearError() close() flush() format(Ljava/lang/String;[Ljava/lang/Object;) format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;) print(C) print(D) print(F) print(I) print(J) print(Ljava/lang/Object;) print(Ljava/lang/String;) print(Z) print([C) printf(Ljava/lang/String;[Ljava/lang/Object;) printf(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;) println() println(C) println(D) println(F) println(I) println(J) println(Ljava/lang/Object;) println(Ljava/lang/String;) println(Z) println([C) setError() write(I) write([B) write([BII) writeBytes([B)",
	},
	"java/io/PrintWriter": {
		supers:  "java/io/Writer",
		methods: "append(C) append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II) checkError() clearError() close() flush() format(Ljava/lang/String;[Ljava/lang/Object;) format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;) print(C) print(D) print(F) print(I) print(J) print(Ljava/lang/Object;) print(Ljava/lang/String;) print(Z) print([C) printf(Ljava/lang/String;[Ljava/lang/Object;) printf(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;) println() println(C) println(D) println(F) println(I) println(J) println(Ljava/lang/Object;) println(Ljava/lang/String;) println(Z) println([C) setError() write(I) write(Ljava/lang/String;) write(Ljava/lang/String;II) write([C) write([CII)",
	},
	"java/io/PushbackInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "available() close() mark(I) markSupported() read() read([BII) reset() skip(J) transferTo(Ljava/io/OutputStream;) unread(I) unread([B) unread([BII)",
	},
	"java/io/PushbackReader": {
		supers:  "java/io/FilterReader",
		methods: "close() mark(I) markSupported() read() read([CII) ready() reset() skip(J) unread(I) unread([C) unread([CII)",
	},
	"java/io/RandomAccessFile": {
		supers:  "java/io/DataOutput java/io/DataInput java/io/Closeable",
		methods: "close() getFilePointer() length() read() read([B) read([BII) seek(J) setLength(J) skipBytes(I) write(I) write([B) write([BII)",
	},
	"java/io/Reader": {
		supers:  "java/lang/Readable java/io/Closeable",
		methods: "close() mark(I) markSupported() read() read(Ljava/nio/CharBuffer;) read([C) read([CII) ready() reset() skip(J) transferTo(Ljava/io/Writer;)",
	},
	"java/io/SequenceInputStream": {
		supers:  "java/io/InputStream",
		methods: "available() close() read() read([BII) transferTo(Ljava/io/OutputStream;)",
	},
	"java/io/Serial": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/io/Serializable": {},
	"java/io/StreamCorruptedException": {
		supers: "java/io/ObjectStreamException",
	},
	"java/io/StreamTokenizer": {
		methods: "commentChar(I) eolIsSignificant(Z) lineno() lowerCaseMode(Z) nextToken() ordinaryChar(I) ordinaryChars(II) parseNumbers() pushBack() quoteChar(I) resetSyntax() slashSlashComments(Z) slashStarComments(Z) toString() whitespaceChars(II) wordChars(II)",
	},
	"java/io/StringBufferInputStream": {
		supers:  "java/io/InputStream",
		methods: "available() read() read([BII) reset() skip(J)",
	},
	"java/io/StringReader": {
		supers:  "java/io/Reader",
		methods: "close() mark(I) markSupported() read() read([CII) ready() reset() skip(J)",
	},
	"java/io/StringWriter": {
		supers:  "java/io/Writer",
		methods: "append(C) append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II) close() flush() getBuffer() toString() write(I) write(Ljava/lang/String;) write(Ljava/lang/String;II) write([CII)",
	},
	"java/io/SyncFailedException": {
		supers: "java/io/IOException",
	},
	"java/io/UTFDataFormatException": {
		supers: "java/io/IOException",
	},
	"java/io/UncheckedIOException": {
		supers:  "java/lang/RuntimeException",
		methods: "getCause()",
	},
	"java/io/UnsupportedEncodingException": {
		supers: "java/io/IOException",
	},
	"java/io/WriteAbortedException": {
		supers:  "java/io/ObjectStreamException",
		methods: "getCause() getMessage()",
	},
	"java/io/Writer": {
		supers:  "java/lang/Appendable java/io/Closeable java/io/Flushable",
		methods: "append(C) append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II) close() flush() write(I) write(Ljava/lang/String;) write(Ljava/lang/String;II) write([C) write([CII)",
	},
	"java/lang/AbstractMethodError": {
		supers: "java/lang/IncompatibleClassChangeError",
	},
	"java/lang/Appendable": {
		methods: "append(C) append(Ljava/lang/CharSequence;) append(Ljava/lang/CharSequence;II)",
	},
	"java/lang/ArithmeticException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/ArrayIndexOutOfBoundsException": {
		supers: "java/lang/IndexOutOfBoundsException",
	},
	"java/lang/ArrayStoreException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/AssertionError": {
		supers: "java/lang/Error",
	},
	"java/lang/AutoCloseable": {
		methods: "close()",
	},
	"java/lang/BootstrapMethodError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/CharSequence": {
		methods: "charAt(I) chars() codePoints() isEmpty() length() subSequence(II) toString()",
	},
	"java/lang/Character$Subset": {},
	"java/lang/ClassCastException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/ClassCircularityError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/ClassFormatError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/ClassLoader": {
		methods: "clearAssertionStatus() definePackage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/net/URL;) findClass(Ljava/lang/String;) findClass(Ljava/lang/String;Ljava/lang/String;) findLibrary(Ljava/lang/String;) findResource(Ljava/lang/String;) findResource(Ljava/lang/String;Ljava/lang/String;) findResources(Ljava/lang/String;) getClassLoadingLock(Ljava/lang/String;) getName() getPackage(Ljava/lang/String;) getPackages() getResource(Ljava/lang/String;) getResourceAsStream(Ljava/lang/String;) getResources(Ljava/lang/String;) loadClass(Ljava/lang/String;) loadClass(Ljava/lang/String;Z) resources(Ljava/lang/String;) setClassAssertionStatus(Ljava/lang/String;Z) setDefaultAssertionStatus(Z) setPackageAssertionStatus(Ljava/lang/String;Z)",
	},
	"java/lang/ClassNotFoundException": {
		supers:  "java/lang/ReflectiveOperationException",
		methods: "getException()",
	},
	"java/lang/ClassValue": {
		methods: "computeValue(Ljava/lang/Class;) get(Ljava/lang/Class;) remove(Ljava/lang/Class;)",
	},
	"java/lang/CloneNotSupportedException": {
		supers: "java/lang/Exception",
	},
	"java/lang/Cloneable": {},
	"java/lang/Comparable": {
		methods: "compareTo(Ljava/lang/Object;)",
	},
	"java/lang/Deprecated": {
		supers:  "java/lang/annotation/Annotation",
		methods: "forRemoval() since()",
	},
	"java/lang/Enum": {
		supers:  "java/lang/constant/Constable java/lang/Comparable java/io/Serializable",
		methods: "compareTo(Ljava/lang/Object;) toString()",
	},
	"java/lang/EnumConstantNotPresentException": {
		supers:  "java/lang/RuntimeException",
		methods: "constantName() enumType()",
	},
	"java/lang/Error": {
		supers: "java/lang/Throwable",
	},
	"java/lang/Exception": {
		supers: "java/lang/Throwable",
	},
	"java/lang/ExceptionInInitializerError": {
		supers:  "java/lang/LinkageError",
		methods: "getException()",
	},
	"java/lang/FunctionalInterface": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/lang/IllegalAccessError": {
		supers: "java/lang/IncompatibleClassChangeError",
	},
	"java/lang/IllegalAccessException": {
		supers: "java/lang/ReflectiveOperationException",
	},
	"java/lang/IllegalArgumentException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/IllegalCallerException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/IllegalMonitorStateException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/IllegalStateException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/IllegalThreadStateException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/lang/IncompatibleClassChangeError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/IndexOutOfBoundsException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/InheritableThreadLocal": {
		supers:  "java/lang/ThreadLocal",
		methods: "childValue(Ljava/lang/Object;)",
	},
	"java/lang/InstantiationError": {
		supers: "java/lang/IncompatibleClassChangeError",
	},
	"java/lang/InstantiationException": {
		supers: "java/lang/ReflectiveOperationException",
	},
	"java/lang/InternalError": {
		supers: "java/lang/VirtualMachineError",
	},
	"java/lang/InterruptedException": {
		supers: "java/lang/Exception",
	},
	"java/lang/Iterable": {
		methods: "forEach(Ljava/util/function/Consumer;) iterator() spliterator()",
	},
	"java/lang/LayerInstantiationException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/LinkageError": {
		supers: "java/lang/Error",
	},
	"java/lang/LiveStackFrame$PrimitiveSlot": {
		methods: "intValue() longValue() size()",
	},
	"java/lang/NamedPackage": {},
	"java/lang/NegativeArraySizeException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/NoClassDefFoundError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/NoSuchFieldError": {
		supers: "java/lang/IncompatibleClassChangeError",
	},
	"java/lang/NoSuchFieldException": {
		supers: "java/lang/ReflectiveOperationException",
	},
	"java/lang/NoSuchMethodError": {
		supers: "java/lang/IncompatibleClassChangeError",
	},
	"java/lang/NoSuchMethodException": {
		supers: "java/lang/ReflectiveOperationException",
	},
	"java/lang/NullPointerException": {
		supers:  "java/lang/RuntimeException",
		methods: "fillInStackTrace() getMessage()",
	},
	"java/lang/Number": {
		supers:  "java/io/Serializable",
		methods: "byteValue() doubleValue() floatValue() intValue() longValue() shortValue()",
	},
	"java/lang/NumberFormatException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/lang/OutOfMemoryError": {
		supers: "java/lang/VirtualMachineError",
	},
	"java/lang/Override": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/lang/Package": {
		supers:  "java/lang/NamedPackage java/lang/reflect/AnnotatedElement",
		methods: "getAnnotation(Ljava/lang/Class;) getAnnotations() getAnnotationsByType(Ljava/lang/Class;) getDeclaredAnnotation(Ljava/lang/Class;) getDeclaredAnnotations() getDeclaredAnnotationsByType(Ljava/lang/Class;) getImplementationTitle() getImplementationVendor() getImplementationVersion() getName() getSpecificationTitle() getSpecificationVendor() getSpecificationVersion() hashCode() isAnnotationPresent(Ljava/lang/Class;) isCompatibleWith(Ljava/lang/String;) isSealed() isSealed(Ljava/net/URL;) toString()",
	},
	"java/lang/Process": {
		methods: "children() descendants() destroy() destroyForcibly() exitValue() getErrorStream() getInputStream() getOutputStream() info() isAlive() onExit() pid() supportsNormalTermination() toHandle() waitFor() waitFor(JLjava/util/concurrent/TimeUnit;)",
	},
	"java/lang/ProcessBuilder$Redirect": {
		methods: "equals(Ljava/lang/Object;) file() hashCode() type()",
	},
	"java/lang/ProcessHandle": {
		supers:  "java/lang/Comparable",
		methods: "children() compareTo(Ljava/lang/Object;) compareTo(Ljava/lang/ProcessHandle;) descendants() destroy() destroyForcibly() equals(Ljava/lang/Object;) hashCode() info() isAlive() onExit() parent() pid() supportsNormalTermination()",
	},
	"java/lang/ProcessHandle$Info": {
		methods: "arguments() command() commandLine() startInstant() totalCpuDuration() user()",
	},
	"java/lang/Readable": {
		methods: "read(Ljava/nio/CharBuffer;)",
	},
	"java/lang/Record": {
		methods: "equals(Ljava/lang/Object;) hashCode() toString()",
	},
	"java/lang/ReflectiveOperationException": {
		supers: "java/lang/Exception",
	},
	"java/lang/Runnable": {
		methods: "run()",
	},
	"java/lang/Runtime": {
		methods: "addShutdownHook(Ljava/lang/Thread;) availableProcessors() exec(Ljava/lang/String;) exec(Ljava/lang/String;[Ljava/lang/String;) exec(Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;) exec([Ljava/lang/String;) exec([Ljava/lang/String;[Ljava/lang/String;) exec([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;) exit(I) freeMemory() gc() halt(I) load(Ljava/lang/String;) loadLibrary(Ljava/lang/String;) maxMemory() removeShutdownHook(Ljava/lang/Thread;) runFinalization() totalMemory()",
	},
	"java/lang/RuntimeException": {
		supers: "java/lang/Exception",
	},
	"java/lang/SafeVarargs": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/lang/SecurityException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/SecurityManager": {
		methods: "checkAccept(Ljava/lang/String;I) checkAccess(Ljava/lang/Thread;) checkAccess(Ljava/lang/ThreadGroup;) checkConnect(Ljava/lang/String;I) checkConnect(Ljava/lang/String;ILjava/lang/Object;) checkCreateClassLoader() checkDelete(Ljava/lang/String;) checkExec(Ljava/lang/String;) checkExit(I) checkLink(Ljava/lang/String;) checkListen(I) checkMulticast(Ljava/net/InetAddress;) checkMulticast(Ljava/net/InetAddress;B) checkPackageAccess(Ljava/lang/String;) checkPackageDefinition(Ljava/lang/String;) checkPermission(Ljava/security/Permission;) checkPermission(Ljava/security/Permission;Ljava/lang/Object;) checkPrintJobAccess() checkPropertiesAccess() checkPropertyAccess(Ljava/lang/String;) checkRead(Ljava/io/FileDescriptor;) checkRead(Ljava/lang/String;) checkRead(Ljava/lang/String;Ljava/lang/Object;) checkSecurityAccess(Ljava/lang/String;) checkSetFactory() checkWrite(Ljava/io/FileDescriptor;) checkWrite(Ljava/lang/String;) getClassContext() getSecurityContext() getThreadGroup()",
	},
	"java/lang/StackOverflowError": {
		supers: "java/lang/VirtualMachineError",
	},
	"java/lang/StackWalker$StackFrame": {
		methods: "getByteCodeIndex() getClassName() getDeclaringClass() getDescriptor() getFileName() getLineNumber() getMethodName() getMethodType() isNativeMethod() toStackTraceElement()",
	},
	"java/lang/StringIndexOutOfBoundsException": {
		supers: "java/lang/IndexOutOfBoundsException",
	},
	"java/lang/StringTemplate": {
		methods: "fragments() interpolate() process(Ljava/lang/StringTemplate$Processor;) values()",
	},
	"java/lang/StringTemplate$Processor": {
		methods: "process(Ljava/lang/StringTemplate;)",
	},
	"java/lang/SuppressWarnings": {
		supers:  "java/lang/annotation/Annotation",
		methods: "value()",
	},
	"java/lang/System$Logger": {
		methods: "getName() isLoggable(Ljava/lang/System$Logger$Level;) log(Ljava/lang/System$Logger$Level;Ljava/lang/Object;) log(Ljava/lang/System$Logger$Level;Ljava/lang/String;) log(Ljava/lang/System$Logger$Level;Ljava/lang/String;Ljava/lang/Throwable;) log(Ljava/lang/System$Logger$Level;Ljava/lang/String;[Ljava/lang/Object;) log(Ljava/lang/System$Logger$Level;Ljava/util/ResourceBundle;Ljava/lang/String;Ljava/lang/Throwable;) log(Ljava/lang/System$Logger$Level;Ljava/util/ResourceBundle;Ljava/lang/String;[Ljava/lang/Object;) log(Ljava/lang/System$Logger$Level;Ljava/util/function/Supplier;) log(Ljava/lang/System$Logger$Level;Ljava/util/function/Supplier;Ljava/lang/Throwable;)",
	},
	"java/lang/System$LoggerFinder": {
		methods: "getLocalizedLogger(Ljava/lang/String;Ljava/util/ResourceBundle;Ljava/lang/Module;) getLogger(Ljava/lang/String;Ljava/lang/Module;)",
	},
	"java/lang/Thread": {
		supers:  "java/lang/Runnable",
		methods: "clone() countStackFrames() getContextClassLoader() getId() getStackTrace() getState() getUncaughtExceptionHandler() interrupt() isInterrupted() run() setContextClassLoader(Ljava/lang/ClassLoader;) setUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;) start() toString()",
	},
	"java/lang/Thread$UncaughtExceptionHandler": {
		methods: "uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)",
	},
	"java/lang/ThreadDeath": {
		supers: "java/lang/Error",
	},
	"java/lang/ThreadGroup": {
		supers:  "java/lang/Thread$UncaughtExceptionHandler",
		methods: "activeCount() activeGroupCount() enumerate([Ljava/lang/Thread;) enumerate([Ljava/lang/Thread;Z) enumerate([Ljava/lang/ThreadGroup;) enumerate([Ljava/lang/ThreadGroup;Z) isDestroyed() list() toString() uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)",
	},
	"java/lang/ThreadLocal": {
		methods: "get() initialValue() remove() set(Ljava/lang/Object;)",
	},
	"java/lang/Throwable": {
		supers:  "java/io/Serializable",
		methods: "fillInStackTrace() getCause() getLocalizedMessage() getMessage() getStackTrace() initCause(Ljava/lang/Throwable;) printStackTrace() printStackTrace(Ljava/io/PrintStream;) printStackTrace(Ljava/io/PrintWriter;) setStackTrace([Ljava/lang/StackTraceElement;) toString()",
	},
	"java/lang/TypeNotPresentException": {
		supers:  "java/lang/RuntimeException",
		methods: "typeName()",
	},
	"java/lang/UnknownError": {
		supers: "java/lang/VirtualMachineError",
	},
	"java/lang/UnsatisfiedLinkError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/UnsupportedClassVersionError": {
		supers: "java/lang/ClassFormatError",
	},
	"java/lang/UnsupportedOperationException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/VerifyError": {
		supers: "java/lang/LinkageError",
	},
	"java/lang/VirtualMachineError": {
		supers: "java/lang/Error",
	},
	"java/lang/annotation/Annotation": {
		methods: "annotationType() equals(Ljava/lang/Object;) hashCode() toString()",
	},
	"java/lang/annotation/AnnotationFormatError": {
		supers: "java/lang/Error",
	},
	"java/lang/annotation/AnnotationTypeMismatchException": {
		supers:  "java/lang/RuntimeException",
		methods: "element() foundType()",
	},
	"java/lang/annotation/Documented": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/lang/annotation/IncompleteAnnotationException": {
		supers:  "java/lang/RuntimeException",
		methods: "annotationType() elementName()",
	},
	"java/lang/annotation/Inherited": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/lang/annotation/Native": {
		supers: "java/lang/annotation/Annotation",
	},
	"java/lang/annotation/Repeatable": {
		supers:  "java/lang/annotation/Annotation",
		methods: "value()",
	},
	"java/lang/annotation/Retention": {
		supers:  "java/lang/annotation/Annotation",
		methods: "value()",
	},
	"java/lang/annotation/Target": {
		supers:  "java/lang/annotation/Annotation",
		methods: "value()",
	},
	"java/lang/constant/Constable": {
		methods: "describeConstable()",
	},
	"java/lang/constant/ConstantDesc": {
		methods: "resolveConstantDesc(Ljava/lang/invoke/MethodHandles$Lookup;)",
	},
	"java/lang/constant/DynamicCallSiteDesc": {
		methods: "bootstrapArgs() bootstrapMethod() invocationName() invocationType() resolveCallSiteDesc(Ljava/lang/invoke/MethodHandles$Lookup;) toString() withArgs([Ljava/lang/constant/ConstantDesc;) withNameAndType(Ljava/lang/String;Ljava/lang/constant/MethodTypeDesc;)",
	},
	"java/lang/constant/DynamicConstantDesc": {
		supers:  "java/lang/constant/ConstantDesc",
		methods: "bootstrapArgs() bootstrapArgsList() bootstrapMethod() constantName() constantType() resolveConstantDesc(Ljava/lang/invoke/MethodHandles$Lookup;) toString()",
	},
	"java/lang/foreign/Arena": {
		supers:  "java/lang/foreign/SegmentAllocator java/lang/AutoCloseable",
		methods: "allocate(JJ) close() scope()",
	},
	"java/lang/foreign/SegmentAllocator": {
		methods: "allocate(J) allocate(JJ) allocate(Ljava/lang/foreign/AddressLayout;Ljava/lang/foreign/MemorySegment;) allocate(Ljava/lang/foreign/MemoryLayout;) allocate(Ljava/lang/foreign/ValueLayout$OfByte;B) allocate(Ljava/lang/foreign/ValueLayout$OfChar;C) allocate(Ljava/lang/foreign/ValueLayout$OfDouble;D) allocate(Ljava/lang/foreign/ValueLayout$OfFloat;F) allocate(Ljava/lang/foreign/ValueLayout$OfInt;I) allocate(Ljava/lang/foreign/ValueLayout$OfLong;J) allocate(Ljava/lang/foreign/ValueLayout$OfShort;S) allocateArray(Ljava/lang/foreign/MemoryLayout;J) allocateArray(Ljava/lang/foreign/ValueLayout$OfByte;[B) allocateArray(Ljava/lang/foreign/ValueLayout$OfChar;[C) allocateArray(Ljava/lang/foreign/ValueLayout$OfDouble;[D) allocateArray(Ljava/lang/foreign/ValueLayout$OfFloat;[F) allocateArray(Ljava/lang/foreign/ValueLayout$OfInt;[I) allocateArray(Ljava/lang/foreign/ValueLayout$OfLong;[J) allocateArray(Ljava/lang/foreign/ValueLayout$OfShort;[S) allocateUtf8String(Ljava/lang/String;)",
	},
	"java/lang/foreign/SymbolLookup": {
		methods: "find(Ljava/lang/String;) or(Ljava/lang/foreign/SymbolLookup;)",
	},
	"java/lang/invoke/CallSite": {
		methods: "dynamicInvoker() getTarget() setTarget(Ljava/lang/invoke/MethodHandle;) type()",
	},
	"java/lang/invoke/ConstantCallSite": {
		supers: "java/lang/invoke/CallSite",
	},
	"java/lang/invoke/LambdaConversionException": {
		supers: "java/lang/Exception",
	},
	"java/lang/invoke/MethodHandleInfo": {
		methods: "getDeclaringClass() getMethodType() getModifiers() getName() getReferenceKind() isVarArgs() reflectAs(Ljava/lang/Class;Ljava/lang/invoke/MethodHandles$Lookup;)",
	},
	"java/lang/invoke/MethodHandleProxies": {},
	"java/lang/invoke/MethodHandles":       {},
	"java/lang/invoke/MutableCallSite": {
		supers:  "java/lang/invoke/CallSite",
		methods: "setTarget(Ljava/lang/invoke/MethodHandle;)",
	},
	"java/lang/invoke/StringConcatException": {
		supers: "java/lang/Exception",
	},
	"java/lang/invoke/SwitchPoint": {
		methods: "guardWithTest(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle;) hasBeenInvalidated()",
	},
	"java/lang/invoke/TypeDescriptor": {
		methods: "descriptorString()",
	},
	"java/lang/invoke/TypeDescriptor$OfField": {
		supers:  "java/lang/invoke/TypeDescriptor",
		methods: "arrayType() componentType() isArray() isPrimitive()",
	},
	"java/lang/invoke/TypeDescriptor$OfMethod": {
		supers:  "java/lang/invoke/TypeDescriptor",
		methods: "changeParameterType(ILjava/lang/invoke/TypeDescriptor$OfField;) changeReturnType(Ljava/lang/invoke/TypeDescriptor$OfField;) dropParameterTypes(II) insertParameterTypes(I[Ljava/lang/invoke/TypeDescriptor$OfField;) parameterArray() parameterCount() parameterList() parameterType(I) returnType()",
	},
	"java/lang/invoke/VolatileCallSite": {
		supers:  "java/lang/invoke/CallSite",
		methods: "setTarget(Ljava/lang/invoke/MethodHandle;)",
	},
	"java/lang/invoke/WrongMethodTypeException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/module/FindException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/module/InvalidModuleDescriptorException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/module/ModuleDescriptor": {
		supers:  "java/lang/Comparable",
		methods: "accessFlags() compareTo(Ljava/lang/Object;) compareTo(Ljava/lang/module/ModuleDescriptor;) equals(Ljava/lang/Object;) exports() hashCode() isAutomatic() isOpen() mainClass() modifiers() name() opens() packages() provides() rawVersion() requires() toNameAndVersion() toString() uses() version()",
	},
	"java/lang/module/ModuleFinder": {
		methods: "find(Ljava/lang/String;) findAll()",
	},
	"java/lang/module/ModuleReader": {
		supers:  "java/io/Closeable",
		methods: "close() find(Ljava/lang/String;) list() open(Ljava/lang/String;) read(Ljava/lang/String;) release(Ljava/nio/ByteBuffer;)",
	},
	"java/lang/module/ModuleReference": {
		methods: "open()",
	},
	"java/lang/module/ResolutionException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/ref/Cleaner$Cleanable": {
		methods: "clean()",
	},
	"java/lang/ref/PhantomReference": {
		supers:  "java/lang/ref/Reference",
		methods: "get()",
	},
	"java/lang/ref/Reference": {
		methods: "clear() clone() enqueue() get() isEnqueued()",
	},
	"java/lang/ref/ReferenceQueue": {
		methods: "poll() remove() remove(J)",
	},
	"java/lang/ref/SoftReference": {
		supers:  "java/lang/ref/Reference",
		methods: "get()",
	},
	"java/lang/ref/WeakReference": {
		supers: "java/lang/ref/Reference",
	},
	"java/lang/reflect/AccessibleObject": {
		supers:  "java/lang/reflect/AnnotatedElement",
		methods: "getAnnotation(Ljava/lang/Class;) getAnnotations() getAnnotationsByType(Ljava/lang/Class;) getDeclaredAnnotation(Ljava/lang/Class;) getDeclaredAnnotations() getDeclaredAnnotationsByType(Ljava/lang/Class;) isAccessible() isAnnotationPresent(Ljava/lang/Class;) setAccessible(Z)",
	},
	"java/lang/reflect/AnnotatedArrayType": {
		supers:  "java/lang/reflect/AnnotatedType",
		methods: "getAnnotatedGenericComponentType() getAnnotatedOwnerType()",
	},
	"java/lang/reflect/AnnotatedElement": {
		methods: "getAnnotation(Ljava/lang/Class;) getAnnotations() getAnnotationsByType(Ljava/lang/Class;) getDeclaredAnnotation(Ljava/lang/Class;) getDeclaredAnnotations() getDeclaredAnnotationsByType(Ljava/lang/Class;) isAnnotationPresent(Ljava/lang/Class;)",
	},
	"java/lang/reflect/AnnotatedParameterizedType": {
		supers:  "java/lang/reflect/AnnotatedType",
		methods: "getAnnotatedActualTypeArguments() getAnnotatedOwnerType()",
	},
	"java/lang/reflect/AnnotatedType": {
		supers:  "java/lang/reflect/AnnotatedElement",
		methods: "getAnnotatedOwnerType() getAnnotation(Ljava/lang/Class;) getAnnotations() getDeclaredAnnotations() getType()",
	},
	"java/lang/reflect/AnnotatedTypeVariable": {
		supers:  "java/lang/reflect/AnnotatedType",
		methods: "getAnnotatedBounds() getAnnotatedOwnerType()",
	},
	"java/lang/reflect/AnnotatedWildcardType": {
		supers:  "java/lang/reflect/AnnotatedType",
		methods: "getAnnotatedLowerBounds() getAnnotatedOwnerType() getAnnotatedUpperBounds()",
	},
	"java/lang/reflect/GenericArrayType": {
		supers:  "java/lang/reflect/Type",
		methods: "getGenericComponentType()",
	},
	"java/lang/reflect/GenericDeclaration": {
		supers:  "java/lang/reflect/AnnotatedElement",
		methods: "getTypeParameters()",
	},
	"java/lang/reflect/GenericSignatureFormatError": {
		supers: "java/lang/ClassFormatError",
	},
	"java/lang/reflect/InaccessibleObjectException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/reflect/InvocationHandler": {
		methods: "invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)",
	},
	"java/lang/reflect/InvocationTargetException": {
		supers:  "java/lang/ReflectiveOperationException",
		methods: "getCause() getTargetException()",
	},
	"java/lang/reflect/MalformedParameterizedTypeException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/reflect/MalformedParametersException": {
		supers: "java/lang/RuntimeException",
	},
	"java/lang/reflect/Member": {
		methods: "accessFlags() getDeclaringClass() getModifiers() getName() isSynthetic()",
	},
	"java/lang/reflect/Modifier": {},
	"java/lang/reflect/ParameterizedType": {
		supers:  "java/lang/reflect/Type",
		methods: "getActualTypeArguments() getOwnerType() getRawType()",
	},
	"java/lang/reflect/Proxy": {
		supers: "java/io/Serializable",
	},
	"java/lang/reflect/Type": {
		methods: "getTypeName()",
	},
	"java/lang/reflect/TypeVariable": {
		supers:  "java/lang/reflect/Type java/lang/reflect/AnnotatedElement",
		methods: "getAnnotatedBounds() getBounds() getGenericDeclaration() getName()",
	},
	"java/lang/reflect/UndeclaredThrowableException": {
		supers:  "java/lang/RuntimeException",
		methods: "getUndeclaredThrowable()",
	},
	"java/lang/reflect/WildcardType": {
		supers:  "java/lang/reflect/Type",
		methods: "getLowerBounds() getUpperBounds()",
	},
	"java/lang/runtime/ObjectMethods":    {},
	"java/lang/runtime/SwitchBootstraps": {},
	"java/math/BigDecimal": {
		supers:  "java/lang/Number java/lang/Comparable",
		methods: "abs() abs(Ljava/math/MathContext;) add(Ljava/math/BigDecimal;) add(Ljava/math/BigDecimal;Ljava/math/MathContext;) byteValueExact() compareTo(Ljava/lang/Object;) compareTo(Ljava/math/BigDecimal;) divide(Ljava/math/BigDecimal;) divide(Ljava/math/BigDecimal;I) divide(Ljava/math/BigDecimal;II) divide(Ljava/math/BigDecimal;ILjava/math/RoundingMode;) divide(Ljava/math/BigDecimal;Ljava/math/MathContext;) divide(Ljava/math/BigDecimal;Ljava/math/RoundingMode;) divideAndRemainder(Ljava/math/BigDecimal;) divideAndRemainder(Ljava/math/BigDecimal;Ljava/math/MathContext;) divideToIntegralValue(Ljava/math/BigDecimal;) divideToIntegralValue(Ljava/math/BigDecimal;Ljava/math/MathContext;) doubleValue() equals(Ljava/lang/Object;) floatValue() hashCode() intValue() intValueExact() longValue() longValueExact() max(Ljava/math/BigDecimal;) min(Ljava/math/BigDecimal;) movePointLeft(I) movePointRight(I) multiply(Ljava/math/BigDecimal;) multiply(Ljava/math/BigDecimal;Ljava/math/MathContext;) negate() negate(Ljava/math/MathContext;) plus() plus(Ljava/math/MathContext;) pow(I) pow(ILjava/math/MathContext;) precision() remainder(Ljava/math/BigDecimal;) remainder(Ljava/math/BigDecimal;Ljava/math/MathContext;) round(Ljava/math/MathContext;) scale() scaleByPowerOfTen(I) setScale(I) setScale(II) setScale(ILjava/math/RoundingMode;) shortValueExact() signum() sqrt(Ljava/math/MathContext;) stripTrailingZeros() subtract(Ljava/math/BigDecimal;) subtract(Ljava/math/BigDecimal;Ljava/math/MathContext;) toBigInteger() toBigIntegerExact() toEngineeringString() toPlainString() toString() ulp() unscaledValue()",
	},
	"java/math/BigInteger": {
		supers:  "java/lang/Number java/lang/Comparable",
		methods: "abs() add(Ljava/math/BigInteger;) and(Ljava/math/BigInteger;) andNot(Ljava/math/BigInteger;) bitCount() bitLength() byteValueExact() clearBit(I) compareTo(Ljava/lang/Object;) compareTo(Ljava/math/BigInteger;) divide(Ljava/math/BigInteger;) divideAndRemainder(Ljava/math/BigInteger;) doubleValue() equals(Ljava/lang/Object;) flipBit(I) floatValue() gcd(Ljava/math/BigInteger;) getLowestSetBit() hashCode() intValue() intValueExact() isProbablePrime(I) longValue() longValueExact() max(Ljava/math/BigInteger;) min(Ljava/math/BigInteger;) mod(Ljava/math/BigInteger;) modInverse(Ljava/math/BigInteger;) modPow(Ljava/math/BigInteger;Ljava/math/BigInteger;) multiply(Ljava/math/BigInteger;) negate() nextProbablePrime() not() or(Ljava/math/BigInteger;) parallelMultiply(Ljava/math/BigInteger;) pow(I) remainder(Ljava/math/BigInteger;) setBit(I) shiftLeft(I) shiftRight(I) shortValueExact() signum() sqrt() sqrtAndRemainder() subtract(Ljava/math/BigInteger;) testBit(I) toByteArray() toString() toString(I) xor(Ljava/math/BigInteger;)",
	},
	"java/net/Authenticator": {
		methods: "getPasswordAuthentication() getRequestingURL() getRequestorType() requestPasswordAuthenticationInstance(Ljava/lang/String;Ljava/net/InetAddress;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/net/URL;Ljava/net/Authenticator$RequestorType;)",
	},
	"java/net/BindException": {
		supers: "java/net/SocketException",
	},
	"java/net/CacheRequest": {
		methods: "abort() getBody()",
	},
	"java/net/CacheResponse": {
		methods: "getBody() getHeaders()",
	},
	"java/net/ConnectException": {
		supers: "java/net/SocketException",
	},
	"java/net/ContentHandler": {
		methods: "getContent(Ljava/net/URLConnection;) getContent(Ljava/net/URLConnection;[Ljava/lang/Class;)",
	},
	"java/net/ContentHandlerFactory": {
		methods: "createContentHandler(Ljava/lang/String;)",
	},
	"java/net/CookieHandler": {
		methods: "get(Ljava/net/URI;Ljava/util/Map;) put(Ljava/net/URI;Ljava/util/Map;)",
	},
	"java/net/CookieManager": {
		supers:  "java/net/CookieHandler",
		methods: "get(Ljava/net/URI;Ljava/util/Map;) getCookieStore() put(Ljava/net/URI;Ljava/util/Map;) setCookiePolicy(Ljava/net/CookiePolicy;)",
	},
	"java/net/CookiePolicy": {
		methods: "shouldAccept(Ljava/net/URI;Ljava/net/HttpCookie;)",
	},
	"java/net/CookieStore": {
		methods: "add(Ljava/net/URI;Ljava/net/HttpCookie;) get(Ljava/net/URI;) getCookies() getURIs() remove(Ljava/net/URI;Ljava/net/HttpCookie;) removeAll()",
	},
	"java/net/DatagramSocket": {
		supers:  "java/io/Closeable",
		methods: "bind(Ljava/net/SocketAddress;) close() connect(Ljava/net/InetAddress;I) connect(Ljava/net/SocketAddress;) disconnect() getBroadcast() getChannel() getInetAddress() getLocalAddress() getLocalPort() getLocalSocketAddress() getOption(Ljava/net/SocketOption;) getPort() getReceiveBufferSize() getRemoteSocketAddress() getReuseAddress() getSendBufferSize() getSoTimeout() getTrafficClass() isBound() isClosed() isConnected() joinGroup(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;) leaveGroup(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;) receive(Ljava/net/DatagramPacket;) send(Ljava/net/DatagramPacket;) setBroadcast(Z) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) setReceiveBufferSize(I) setReuseAddress(Z) setSendBufferSize(I) setSoTimeout(I) setTrafficClass(I) supportedOptions()",
	},
	"java/net/DatagramSocketImpl": {
		supers:  "java/net/SocketOptions",
		methods: "bind(ILjava/net/InetAddress;) close() connect(Ljava/net/InetAddress;I) create() disconnect() getFileDescriptor() getLocalPort() getOption(Ljava/net/SocketOption;) getTTL() getTimeToLive() join(Ljava/net/InetAddress;) joinGroup(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;) leave(Ljava/net/InetAddress;) leaveGroup(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;) peek(Ljava/net/InetAddress;) peekData(Ljava/net/DatagramPacket;) receive(Ljava/net/DatagramPacket;) send(Ljava/net/DatagramPacket;) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) setTTL(B) setTimeToLive(I) supportedOptions()",
	},
	"java/net/DatagramSocketImplFactory": {
		methods: "createDatagramSocketImpl()",
	},
	"java/net/FileNameMap": {
		methods: "getContentTypeFor(Ljava/lang/String;)",
	},
	"java/net/HttpRetryException": {
		supers:  "java/io/IOException",
		methods: "getLocation() getReason() responseCode()",
	},
	"java/net/HttpURLConnection": {
		supers:  "java/net/URLConnection",
		methods: "disconnect() getErrorStream() getHeaderField(I) getHeaderFieldDate(Ljava/lang/String;J) getHeaderFieldKey(I) getInstanceFollowRedirects() getPermission() getRequestMethod() getResponseCode() getResponseMessage() setAuthenticator(Ljava/net/Authenticator;) setChunkedStreamingMode(I) setFixedLengthStreamingMode(I) setFixedLengthStreamingMode(J) setInstanceFollowRedirects(Z) setRequestMethod(Ljava/lang/String;) usingProxy()",
	},
	"java/net/InetSocketAddress": {
		supers:  "java/net/SocketAddress",
		methods: "toString()",
	},
	"java/net/InterfaceAddress": {
		methods: "equals(Ljava/lang/Object;) getAddress() getBroadcast() getNetworkPrefixLength() hashCode() toString()",
	},
	"java/net/JarURLConnection": {
		supers:  "java/net/URLConnection",
		methods: "getAttributes() getCertificates() getEntryName() getJarEntry() getJarFile() getJarFileURL() getMainAttributes() getManifest()",
	},
	"java/net/MalformedURLException": {
		supers: "java/io/IOException",
	},
	"java/net/MulticastSocket": {
		supers:  "java/net/DatagramSocket",
		methods: "getInterface() getLoopbackMode() getNetworkInterface() getTTL() getTimeToLive() joinGroup(Ljava/net/InetAddress;) joinGroup(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;) leaveGroup(Ljava/net/InetAddress;) leaveGroup(Ljava/net/SocketAddress;Ljava/net/NetworkInterface;) send(Ljava/net/DatagramPacket;B) setInterface(Ljava/net/InetAddress;) setLoopbackMode(Z) setNetworkInterface(Ljava/net/NetworkInterface;) setTTL(B) setTimeToLive(I)",
	},
	"java/net/NoRouteToHostException": {
		supers: "java/net/SocketException",
	},
	"java/net/PortUnreachableException": {
		supers: "java/net/SocketException",
	},
	"java/net/ProtocolException": {
		supers: "java/io/IOException",
	},
	"java/net/ProtocolFamily": {
		methods: "name()",
	},
	"java/net/Proxy": {
		methods: "address() toString() type()",
	},
	"java/net/ProxySelector": {
		methods: "connectFailed(Ljava/net/URI;Ljava/net/SocketAddress;Ljava/io/IOException;) select(Ljava/net/URI;)",
	},
	"java/net/ResponseCache": {
		methods: "get(Ljava/net/URI;Ljava/lang/String;Ljava/util/Map;) put(Ljava/net/URI;Ljava/net/URLConnection;)",
	},
	"java/net/SecureCacheResponse": {
		supers:  "java/net/CacheResponse",
		methods: "getCipherSuite() getLocalCertificateChain() getLocalPrincipal() getPeerPrincipal() getSSLSession() getServerCertificateChain()",
	},
	"java/net/ServerSocket": {
		supers:  "java/io/Closeable",
		methods: "accept() bind(Ljava/net/SocketAddress;) bind(Ljava/net/SocketAddress;I) close() getChannel() getInetAddress() getLocalPort() getLocalSocketAddress() getOption(Ljava/net/SocketOption;) getReceiveBufferSize() getReuseAddress() getSoTimeout() isBound() isClosed() setOption(Ljava/net/SocketOption;Ljava/lang/Object;) setPerformancePreferences(III) setReceiveBufferSize(I) setReuseAddress(Z) setSoTimeout(I) supportedOptions() toString()",
	},
	"java/net/Socket": {
		supers:  "java/io/Closeable",
		methods: "bind(Ljava/net/SocketAddress;) close() connect(Ljava/net/SocketAddress;) connect(Ljava/net/SocketAddress;I) getChannel() getInetAddress() getInputStream() getKeepAlive() getLocalAddress() getLocalPort() getLocalSocketAddress() getOOBInline() getOption(Ljava/net/SocketOption;) getOutputStream() getPort() getReceiveBufferSize() getRemoteSocketAddress() getReuseAddress() getSendBufferSize() getSoLinger() getSoTimeout() getTcpNoDelay() getTrafficClass() isBound() isClosed() isConnected() isInputShutdown() isOutputShutdown() sendUrgentData(I) setKeepAlive(Z) setOOBInline(Z) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) setPerformancePreferences(III) setReceiveBufferSize(I) setReuseAddress(Z) setSendBufferSize(I) setSoLinger(ZI) setSoTimeout(I) setTcpNoDelay(Z) setTrafficClass(I) shutdownInput() shutdownOutput() supportedOptions() toString()",
	},
	"java/net/SocketAddress": {
		supers: "java/io/Serializable",
	},
	"java/net/SocketException": {
		supers: "java/io/IOException",
	},
	"java/net/SocketImpl": {
		supers:  "java/net/SocketOptions",
		methods: "accept(Ljava/net/SocketImpl;) available() bind(Ljava/net/InetAddress;I) close() connect(Ljava/lang/String;I) connect(Ljava/net/InetAddress;I) connect(Ljava/net/SocketAddress;I) create(Z) getFileDescriptor() getInetAddress() getInputStream() getLocalPort() getOption(Ljava/net/SocketOption;) getOutputStream() getPort() listen(I) sendUrgentData(I) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) setPerformancePreferences(III) shutdownInput() shutdownOutput() supportedOptions() supportsUrgentData() toString()",
	},
	"java/net/SocketImplFactory": {
		methods: "createSocketImpl()",
	},
	"java/net/SocketOption": {
		methods: "name() type()",
	},
	"java/net/SocketOptions": {
		methods: "getOption(I) setOption(ILjava/lang/Object;)",
	},
	"java/net/SocketTimeoutException": {
		supers: "java/io/InterruptedIOException",
	},
	"java/net/URISyntaxException": {
		supers:  "java/lang/Exception",
		methods: "getIndex() getInput() getMessage() getReason()",
	},
	"java/net/URLClassLoader": {
		supers:  "java/security/SecureClassLoader java/io/Closeable",
		methods: "addURL(Ljava/net/URL;) close() definePackage(Ljava/lang/String;Ljava/util/jar/Manifest;Ljava/net/URL;) findClass(Ljava/lang/String;) findResource(Ljava/lang/String;) findResources(Ljava/lang/String;) getPermissions(Ljava/security/CodeSource;) getResourceAsStream(Ljava/lang/String;) getURLs()",
	},
	"java/net/URLConnection": {
		methods: "addRequestProperty(Ljava/lang/String;Ljava/lang/String;) connect() getAllowUserInteraction() getConnectTimeout() getContent() getContent([Ljava/lang/Class;) getContentEncoding() getContentLength() getContentLengthLong() getContentType() getDate() getDefaultUseCaches() getDoInput() getDoOutput() getExpiration() getHeaderField(I) getHeaderField(Ljava/lang/String;) getHeaderFieldDate(Ljava/lang/String;J) getHeaderFieldInt(Ljava/lang/String;I) getHeaderFieldKey(I) getHeaderFieldLong(Ljava/lang/String;J) getHeaderFields() getIfModifiedSince() getInputStream() getLastModified() getOutputStream() getPermission() getReadTimeout() getRequestProperties() getRequestProperty(Ljava/lang/String;) getURL() getUseCaches() setAllowUserInteraction(Z) setConnectTimeout(I) setDefaultUseCaches(Z) setDoInput(Z) setDoOutput(Z) setIfModifiedSince(J) setReadTimeout(I) setRequestProperty(Ljava/lang/String;Ljava/lang/String;) setUseCaches(Z) toString()",
	},
	"java/net/URLDecoder": {},
	"java/net/URLEncoder": {},
	"java/net/URLStreamHandler": {
		methods: "equals(Ljava/net/URL;Ljava/net/URL;) getDefaultPort() getHostAddress(Ljava/net/URL;) hashCode(Ljava/net/URL;) hostsEqual(Ljava/net/URL;Ljava/net/URL;) openConnection(Ljava/net/URL;) openConnection(Ljava/net/URL;Ljava/net/Proxy;) parseURL(Ljava/net/URL;Ljava/lang/String;II) sameFile(Ljava/net/URL;Ljava/net/URL;) setURL(Ljava/net/URL;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;) setURL(Ljava/net/URL;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;) toExternalForm(Ljava/net/URL;)",
	},
	"java/net/URLStreamHandlerFactory": {
		methods: "createURLStreamHandler(Ljava/lang/String;)",
	},
	"java/net/UnknownHostException": {
		supers: "java/io/IOException",
	},
	"java/net/UnknownServiceException": {
		supers: "java/io/IOException",
	},
	"java/net/spi/InetAddressResolver": {
		methods: "lookupByAddress([B) lookupByName(Ljava/lang/String;Ljava/net/spi/InetAddressResolver$LookupPolicy;)",
	},
	"java/net/spi/InetAddressResolverProvider": {
		methods: "get(Ljava/net/spi/InetAddressResolverProvider$Configuration;) name()",
	},
	"java/net/spi/URLStreamHandlerProvider": {
		supers: "java/net/URLStreamHandlerFactory",
	},
	"java/nio/BufferOverflowException": {
		supers: "java/lang/RuntimeException",
	},
	"java/nio/BufferUnderflowException": {
		supers: "java/lang/RuntimeException",
	},
	"java/nio/InvalidMarkException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/ReadOnlyBufferException": {
		supers: "java/lang/UnsupportedOperationException",
	},
	"java/nio/channels/AcceptPendingException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/AlreadyBoundException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/AlreadyConnectedException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/AsynchronousByteChannel": {
		supers:  "java/nio/channels/AsynchronousChannel",
		methods: "read(Ljava/nio/ByteBuffer;) read(Ljava/nio/ByteBuffer;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;) write(Ljava/nio/ByteBuffer;) write(Ljava/nio/ByteBuffer;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;)",
	},
	"java/nio/channels/AsynchronousChannel": {
		supers:  "java/nio/channels/Channel",
		methods: "close()",
	},
	"java/nio/channels/AsynchronousChannelGroup": {
		methods: "awaitTermination(JLjava/util/concurrent/TimeUnit;) isShutdown() isTerminated() shutdown() shutdownNow()",
	},
	"java/nio/channels/AsynchronousCloseException": {
		supers: "java/nio/channels/ClosedChannelException",
	},
	"java/nio/channels/AsynchronousFileChannel": {
		supers:  "java/nio/channels/AsynchronousChannel",
		methods: "force(Z) lock(JJZ) lock(JJZLjava/lang/Object;Ljava/nio/channels/CompletionHandler;) read(Ljava/nio/ByteBuffer;J) read(Ljava/nio/ByteBuffer;JLjava/lang/Object;Ljava/nio/channels/CompletionHandler;) size() truncate(J) tryLock(JJZ) write(Ljava/nio/ByteBuffer;J) write(Ljava/nio/ByteBuffer;JLjava/lang/Object;Ljava/nio/channels/CompletionHandler;)",
	},
	"java/nio/channels/AsynchronousServerSocketChannel": {
		supers:  "java/nio/channels/AsynchronousChannel java/nio/channels/NetworkChannel",
		methods: "accept() accept(Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;) bind(Ljava/net/SocketAddress;) bind(Ljava/net/SocketAddress;I) getLocalAddress() setOption(Ljava/net/SocketOption;Ljava/lang/Object;)",
	},
	"java/nio/channels/AsynchronousSocketChannel": {
		supers:  "java/nio/channels/AsynchronousByteChannel java/nio/channels/NetworkChannel",
		methods: "bind(Ljava/net/SocketAddress;) connect(Ljava/net/SocketAddress;) connect(Ljava/net/SocketAddress;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;) getLocalAddress() getRemoteAddress() read(Ljava/nio/ByteBuffer;) read(Ljava/nio/ByteBuffer;JLjava/util/concurrent/TimeUnit;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;) read([Ljava/nio/ByteBuffer;IIJLjava/util/concurrent/TimeUnit;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) shutdownInput() shutdownOutput() write(Ljava/nio/ByteBuffer;) write(Ljava/nio/ByteBuffer;JLjava/util/concurrent/TimeUnit;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;) write([Ljava/nio/ByteBuffer;IIJLjava/util/concurrent/TimeUnit;Ljava/lang/Object;Ljava/nio/channels/CompletionHandler;)",
	},
	"java/nio/channels/ByteChannel": {
		supers: "java/nio/channels/ReadableByteChannel java/nio/channels/WritableByteChannel",
	},
	"java/nio/channels/CancelledKeyException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/Channel": {
		supers:  "java/io/Closeable",
		methods: "close() isOpen()",
	},
	"java/nio/channels/ClosedByInterruptException": {
		supers: "java/nio/channels/AsynchronousCloseException",
	},
	"java/nio/channels/ClosedChannelException": {
		supers: "java/io/IOException",
	},
	"java/nio/channels/ClosedSelectorException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/CompletionHandler": {
		methods: "completed(Ljava/lang/Object;Ljava/lang/Object;) failed(Ljava/lang/Throwable;Ljava/lang/Object;)",
	},
	"java/nio/channels/ConnectionPendingException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/DatagramChannel": {
		supers:  "java/nio/channels/spi/AbstractSelectableChannel java/nio/channels/ByteChannel java/nio/channels/ScatteringByteChannel java/nio/channels/GatheringByteChannel java/nio/channels/MulticastChannel",
		methods: "bind(Ljava/net/SocketAddress;) connect(Ljava/net/SocketAddress;) disconnect() getLocalAddress() getRemoteAddress() isConnected() read(Ljava/nio/ByteBuffer;) read([Ljava/nio/ByteBuffer;II) receive(Ljava/nio/ByteBuffer;) send(Ljava/nio/ByteBuffer;Ljava/net/SocketAddress;) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) socket() write(Ljava/nio/ByteBuffer;) write([Ljava/nio/ByteBuffer;II)",
	},
	"java/nio/channels/FileChannel": {
		supers:  "java/nio/channels/spi/AbstractInterruptibleChannel java/nio/channels/SeekableByteChannel java/nio/channels/GatheringByteChannel java/nio/channels/ScatteringByteChannel",
		methods: "force(Z) lock(JJZ) map(Ljava/nio/channels/FileChannel$MapMode;JJ) map(Ljava/nio/channels/FileChannel$MapMode;JJLjava/lang/foreign/Arena;) position() position(J) read(Ljava/nio/ByteBuffer;) read(Ljava/nio/ByteBuffer;J) read([Ljava/nio/ByteBuffer;II) size() transferFrom(Ljava/nio/channels/ReadableByteChannel;JJ) transferTo(JJLjava/nio/channels/WritableByteChannel;) truncate(J) tryLock(JJZ) write(Ljava/nio/ByteBuffer;) write(Ljava/nio/ByteBuffer;J) write([Ljava/nio/ByteBuffer;II)",
	},
	"java/nio/channels/FileChannel$MapMode": {
		methods: "toString()",
	},
	"java/nio/channels/FileLock": {
		supers:  "java/lang/AutoCloseable",
		methods: "acquiredBy() isValid() release()",
	},
	"java/nio/channels/FileLockInterruptionException": {
		supers: "java/io/IOException",
	},
	"java/nio/channels/GatheringByteChannel": {
		supers:  "java/nio/channels/WritableByteChannel",
		methods: "write([Ljava/nio/ByteBuffer;) write([Ljava/nio/ByteBuffer;II)",
	},
	"java/nio/channels/IllegalBlockingModeException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/IllegalChannelGroupException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/nio/channels/IllegalSelectorException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/nio/channels/InterruptedByTimeoutException": {
		supers: "java/io/IOException",
	},
	"java/nio/channels/InterruptibleChannel": {
		supers:  "java/nio/channels/Channel",
		methods: "close()",
	},
	"java/nio/channels/MembershipKey": {
		methods: "block(Ljava/net/InetAddress;) channel() drop() group() isValid() networkInterface() sourceAddress() unblock(Ljava/net/InetAddress;)",
	},
	"java/nio/channels/MulticastChannel": {
		supers:  "java/nio/channels/NetworkChannel",
		methods: "close() join(Ljava/net/InetAddress;Ljava/net/NetworkInterface;) join(Ljava/net/InetAddress;Ljava/net/NetworkInterface;Ljava/net/InetAddress;)",
	},
	"java/nio/channels/NetworkChannel": {
		supers:  "java/nio/channels/Channel",
		methods: "bind(Ljava/net/SocketAddress;) getLocalAddress() getOption(Ljava/net/SocketOption;) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) supportedOptions()",
	},
	"java/nio/channels/NoConnectionPendingException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/NonReadableChannelException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/NonWritableChannelException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/NotYetBoundException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/NotYetConnectedException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/OverlappingFileLockException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/Pipe": {
		methods: "sink() source()",
	},
	"java/nio/channels/Pipe$SinkChannel": {
		supers: "java/nio/channels/spi/AbstractSelectableChannel java/nio/channels/WritableByteChannel java/nio/channels/GatheringByteChannel",
	},
	"java/nio/channels/Pipe$SourceChannel": {
		supers: "java/nio/channels/spi/AbstractSelectableChannel java/nio/channels/ReadableByteChannel java/nio/channels/ScatteringByteChannel",
	},
	"java/nio/channels/ReadPendingException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/ReadableByteChannel": {
		supers:  "java/nio/channels/Channel",
		methods: "read(Ljava/nio/ByteBuffer;)",
	},
	"java/nio/channels/ScatteringByteChannel": {
		supers:  "java/nio/channels/ReadableByteChannel",
		methods: "read([Ljava/nio/ByteBuffer;) read([Ljava/nio/ByteBuffer;II)",
	},
	"java/nio/channels/SeekableByteChannel": {
		supers:  "java/nio/channels/ByteChannel",
		methods: "position() position(J) read(Ljava/nio/ByteBuffer;) size() truncate(J) write(Ljava/nio/ByteBuffer;)",
	},
	"java/nio/channels/SelectableChannel": {
		supers:  "java/nio/channels/spi/AbstractInterruptibleChannel java/nio/channels/Channel",
		methods: "blockingLock() configureBlocking(Z) isBlocking() isRegistered() keyFor(Ljava/nio/channels/Selector;) provider() register(Ljava/nio/channels/Selector;ILjava/lang/Object;) validOps()",
	},
	"java/nio/channels/SelectionKey": {
		methods: "cancel() channel() interestOps() interestOps(I) interestOpsAnd(I) interestOpsOr(I) isValid() readyOps() selector()",
	},
	"java/nio/channels/Selector": {
		supers:  "java/io/Closeable",
		methods: "close() isOpen() keys() provider() select() select(J) select(Ljava/util/function/Consumer;) select(Ljava/util/function/Consumer;J) selectNow() selectNow(Ljava/util/function/Consumer;) selectedKeys() wakeup()",
	},
	"java/nio/channels/ServerSocketChannel": {
		supers:  "java/nio/channels/spi/AbstractSelectableChannel java/nio/channels/NetworkChannel",
		methods: "accept() bind(Ljava/net/SocketAddress;) bind(Ljava/net/SocketAddress;I) getLocalAddress() setOption(Ljava/net/SocketOption;Ljava/lang/Object;) socket()",
	},
	"java/nio/channels/ShutdownChannelGroupException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/SocketChannel": {
		supers:  "java/nio/channels/spi/AbstractSelectableChannel java/nio/channels/ByteChannel java/nio/channels/ScatteringByteChannel java/nio/channels/GatheringByteChannel java/nio/channels/NetworkChannel",
		methods: "bind(Ljava/net/SocketAddress;) connect(Ljava/net/SocketAddress;) finishConnect() getLocalAddress() getRemoteAddress() isConnected() isConnectionPending() read(Ljava/nio/ByteBuffer;) read([Ljava/nio/ByteBuffer;II) setOption(Ljava/net/SocketOption;Ljava/lang/Object;) shutdownInput() shutdownOutput() socket() write(Ljava/nio/ByteBuffer;) write([Ljava/nio/ByteBuffer;II)",
	},
	"java/nio/channels/UnresolvedAddressException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/nio/channels/UnsupportedAddressTypeException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/nio/channels/WritableByteChannel": {
		supers:  "java/nio/channels/Channel",
		methods: "write(Ljava/nio/ByteBuffer;)",
	},
	"java/nio/channels/WritePendingException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/channels/spi/AbstractInterruptibleChannel": {
		supers:  "java/nio/channels/Channel java/nio/channels/InterruptibleChannel",
		methods: "implCloseChannel()",
	},
	"java/nio/channels/spi/AbstractSelectableChannel": {
		supers:  "java/nio/channels/SelectableChannel",
		methods: "implCloseSelectableChannel() implConfigureBlocking(Z)",
	},
	"java/nio/channels/spi/AbstractSelectionKey": {
		supers: "java/nio/channels/SelectionKey",
	},
	"java/nio/channels/spi/AbstractSelector": {
		supers:  "java/nio/channels/Selector",
		methods: "implCloseSelector() register(Ljava/nio/channels/spi/AbstractSelectableChannel;ILjava/lang/Object;)",
	},
	"java/nio/channels/spi/AsynchronousChannelProvider": {
		methods: "openAsynchronousChannelGroup(ILjava/util/concurrent/ThreadFactory;) openAsynchronousChannelGroup(Ljava/util/concurrent/ExecutorService;I) openAsynchronousServerSocketChannel(Ljava/nio/channels/AsynchronousChannelGroup;) openAsynchronousSocketChannel(Ljava/nio/channels/AsynchronousChannelGroup;)",
	},
	"java/nio/channels/spi/SelectorProvider": {
		methods: "inheritedChannel() openDatagramChannel() openDatagramChannel(Ljava/net/ProtocolFamily;) openPipe() openSelector() openServerSocketChannel() openServerSocketChannel(Ljava/net/ProtocolFamily;) openSocketChannel() openSocketChannel(Ljava/net/ProtocolFamily;)",
	},
	"java/nio/charset/CharacterCodingException": {
		supers: "java/io/IOException",
	},
	"java/nio/charset/Charset": {
		supers:  "java/lang/Comparable",
		methods: "canEncode() compareTo(Ljava/lang/Object;) contains(Ljava/nio/charset/Charset;) displayName() displayName(Ljava/util/Locale;) newDecoder() newEncoder()",
	},
	"java/nio/charset/CharsetDecoder": {
		methods: "decodeLoop(Ljava/nio/ByteBuffer;Ljava/nio/CharBuffer;) detectedCharset() implFlush(Ljava/nio/CharBuffer;) implOnMalformedInput(Ljava/nio/charset/CodingErrorAction;) implOnUnmappableCharacter(Ljava/nio/charset/CodingErrorAction;) implReplaceWith(Ljava/lang/String;) implReset() isAutoDetecting() isCharsetDetected() malformedInputAction() unmappableCharacterAction()",
	},
	"java/nio/charset/CharsetEncoder": {
		methods: "canEncode(C) canEncode(Ljava/lang/CharSequence;) encodeLoop(Ljava/nio/CharBuffer;Ljava/nio/ByteBuffer;) implFlush(Ljava/nio/ByteBuffer;) implOnMalformedInput(Ljava/nio/charset/CodingErrorAction;) implOnUnmappableCharacter(Ljava/nio/charset/CodingErrorAction;) implReplaceWith([B) implReset() isLegalReplacement([B) malformedInputAction() unmappableCharacterAction()",
	},
	"java/nio/charset/CoderMalfunctionError": {
		supers: "java/lang/Error",
	},
	"java/nio/charset/CoderResult": {
		methods: "isError() isMalformed() isOverflow() isUnderflow() isUnmappable() length() throwException() toString()",
	},
	"java/nio/charset/CodingErrorAction": {
		methods: "toString()",
	},
	"java/nio/charset/IllegalCharsetNameException": {
		supers:  "java/lang/IllegalArgumentException",
		methods: "getCharsetName()",
	},
	"java/nio/charset/MalformedInputException": {
		supers:  "java/nio/charset/CharacterCodingException",
		methods: "getInputLength() getMessage()",
	},
	"java/nio/charset/UnmappableCharacterException": {
		supers:  "java/nio/charset/CharacterCodingException",
		methods: "getInputLength() getMessage()",
	},
	"java/nio/charset/UnsupportedCharsetException": {
		supers:  "java/lang/IllegalArgumentException",
		methods: "getCharsetName()",
	},
	"java/nio/charset/spi/CharsetProvider": {
		methods: "charsetForName(Ljava/lang/String;) charsets()",
	},
	"java/nio/file/AccessDeniedException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/AtomicMoveNotSupportedException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/ClosedDirectoryStreamException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/file/ClosedFileSystemException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/file/ClosedWatchServiceException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/nio/file/CopyOption": {},
	"java/nio/file/DirectoryNotEmptyException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/DirectoryStream": {
		supers:  "java/io/Closeable java/lang/Iterable",
		methods: "iterator()",
	},
	"java/nio/file/DirectoryStream$Filter": {
		methods: "accept(Ljava/lang/Object;)",
	},
	"java/nio/file/FileAlreadyExistsException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/FileStore": {
		methods: "getAttribute(Ljava/lang/String;) getBlockSize() getFileStoreAttributeView(Ljava/lang/Class;) getTotalSpace() getUnallocatedSpace() getUsableSpace() isReadOnly() name() supportsFileAttributeView(Ljava/lang/Class;) supportsFileAttributeView(Ljava/lang/String;) type()",
	},
	"java/nio/file/FileSystem": {
		supers:  "java/io/Closeable",
		methods: "close() getFileStores() getPath(Ljava/lang/String;[Ljava/lang/String;) getPathMatcher(Ljava/lang/String;) getRootDirectories() getSeparator() getUserPrincipalLookupService() isOpen() isReadOnly() newWatchService() provider() supportedFileAttributeViews()",
	},
	"java/nio/file/FileSystemAlreadyExistsException": {
		supers: "java/lang/RuntimeException",
	},
	"java/nio/file/FileSystemException": {
		supers:  "java/io/IOException",
		methods: "getFile() getMessage() getOtherFile() getReason()",
	},
	"java/nio/file/FileSystemLoopException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/FileSystemNotFoundException": {
		supers: "java/lang/RuntimeException",
	},
	"java/nio/file/FileVisitor": {
		methods: "postVisitDirectory(Ljava/lang/Object;Ljava/io/IOException;) preVisitDirectory(Ljava/lang/Object;Ljava/nio/file/attribute/BasicFileAttributes;) visitFile(Ljava/lang/Object;Ljava/nio/file/attribute/BasicFileAttributes;) visitFileFailed(Ljava/lang/Object;Ljava/io/IOException;)",
	},
	"java/nio/file/InvalidPathException": {
		supers:  "java/lang/IllegalArgumentException",
		methods: "getIndex() getInput() getMessage() getReason()",
	},
	"java/nio/file/NoSuchFileException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/NotDirectoryException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/NotLinkException": {
		supers: "java/nio/file/FileSystemException",
	},
	"java/nio/file/OpenOption": {},
	"java/nio/file/Path": {
		supers:  "java/lang/Comparable java/lang/Iterable java/nio/file/Watchable",
		methods: "compareTo(Ljava/lang/Object;) compareTo(Ljava/nio/file/Path;) endsWith(Ljava/lang/String;) endsWith(Ljava/nio/file/Path;) equals(Ljava/lang/Object;) getFileName() getFileSystem() getName(I) getNameCount() getParent() getRoot() hashCode() isAbsolute() iterator() normalize() register(Ljava/nio/file/WatchService;[Ljava/nio/file/WatchEvent$Kind;) register(Ljava/nio/file/WatchService;[Ljava/nio/file/WatchEvent$Kind;[Ljava/nio/file/WatchEvent$Modifier;) relativize(Ljava/nio/file/Path;) resolve(Ljava/lang/String;) resolve(Ljava/nio/file/Path;) resolveSibling(Ljava/lang/String;) resolveSibling(Ljava/nio/file/Path;) startsWith(Ljava/lang/String;) startsWith(Ljava/nio/file/Path;) subpath(II) toAbsolutePath() toFile() toRealPath([Ljava/nio/file/LinkOption;) toString() toUri()",
	},
	"java/nio/file/PathMatcher": {
		methods: "matches(Ljava/nio/file/Path;)",
	},
	"java/nio/file/ProviderMismatchException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/nio/file/ProviderNotFoundException": {
		supers: "java/lang/RuntimeException",
	},
	"java/nio/file/ReadOnlyFileSystemException": {
		supers: "java/lang/UnsupportedOperationException",
	},
	"java/nio/file/SecureDirectoryStream": {
		supers:  "java/nio/file/DirectoryStream",
		methods: "deleteDirectory(Ljava/lang/Object;) deleteFile(Ljava/lang/Object;) getFileAttributeView(Ljava/lang/Class;) getFileAttributeView(Ljava/lang/Object;Ljava/lang/Class;[Ljava/nio/file/LinkOption;) move(Ljava/lang/Object;Ljava/nio/file/SecureDirectoryStream;Ljava/lang/Object;) newByteChannel(Ljava/lang/Object;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;) newDirectoryStream(Ljava/lang/Object;[Ljava/nio/file/LinkOption;)",
	},
	"java/nio/file/SimpleFileVisitor": {
		supers:  "java/nio/file/FileVisitor",
		methods: "postVisitDirectory(Ljava/lang/Object;Ljava/io/IOException;) preVisitDirectory(Ljava/lang/Object;Ljava/nio/file/attribute/BasicFileAttributes;) visitFile(Ljava/lang/Object;Ljava/nio/file/attribute/BasicFileAttributes;) visitFileFailed(Ljava/lang/Object;Ljava/io/IOException;)",
	},
	"java/nio/file/WatchEvent": {
		methods: "context() count() kind()",
	},
	"java/nio/file/WatchEvent$Kind": {
		methods: "name() type()",
	},
	"java/nio/file/WatchEvent$Modifier": {
		methods: "name()",
	},
	"java/nio/file/WatchKey": {
		methods: "cancel() isValid() pollEvents() reset() watchable()",
	},
	"java/nio/file/WatchService": {
		supers:  "java/io/Closeable",
		methods: "close() poll() poll(JLjava/util/concurrent/TimeUnit;) take()",
	},
	"java/nio/file/Watchable": {
		methods: "register(Ljava/nio/file/WatchService;[Ljava/nio/file/WatchEvent$Kind;) register(Ljava/nio/file/WatchService;[Ljava/nio/file/WatchEvent$Kind;[Ljava/nio/file/WatchEvent$Modifier;)",
	},
	"java/nio/file/attribute/AclFileAttributeView": {
		supers:  "java/nio/file/attribute/FileOwnerAttributeView",
		methods: "getAcl() name() setAcl(Ljava/util/List;)",
	},
	"java/nio/file/attribute/AttributeView": {
		methods: "name()",
	},
	"java/nio/file/attribute/BasicFileAttributeView": {
		supers:  "java/nio/file/attribute/FileAttributeView",
		methods: "name() readAttributes() setTimes(Ljava/nio/file/attribute/FileTime;Ljava/nio/file/attribute/FileTime;Ljava/nio/file/attribute/FileTime;)",
	},
	"java/nio/file/attribute/BasicFileAttributes": {
		methods: "creationTime() fileKey() isDirectory() isOther() isRegularFile() isSymbolicLink() lastAccessTime() lastModifiedTime() size()",
	},
	"java/nio/file/attribute/DosFileAttributeView": {
		supers:  "java/nio/file/attribute/BasicFileAttributeView",
		methods: "name() readAttributes() setArchive(Z) setHidden(Z) setReadOnly(Z) setSystem(Z)",
	},
	"java/nio/file/attribute/DosFileAttributes": {
		supers:  "java/nio/file/attribute/BasicFileAttributes",
		methods: "isArchive() isHidden() isReadOnly() isSystem()",
	},
	"java/nio/file/attribute/FileAttribute": {
		methods: "name() value()",
	},
	"java/nio/file/attribute/FileAttributeView": {
		supers: "java/nio/file/attribute/AttributeView",
	},
	"java/nio/file/attribute/FileOwnerAttributeView": {
		supers:  "java/nio/file/attribute/FileAttributeView",
		methods: "getOwner() name() setOwner(Ljava/nio/file/attribute/UserPrincipal;)",
	},
	"java/nio/file/attribute/FileStoreAttributeView": {
		supers: "java/nio/file/attribute/AttributeView",
	},
	"java/nio/file/attribute/GroupPrincipal": {
		supers: "java/nio/file/attribute/UserPrincipal",
	},
	"java/nio/file/attribute/PosixFileAttributeView": {
		supers:  "java/nio/file/attribute/BasicFileAttributeView java/nio/file/attribute/FileOwnerAttributeView",
		methods: "name() readAttributes() setGroup(Ljava/nio/file/attribute/GroupPrincipal;) setPermissions(Ljava/util/Set;)",
	},
	"java/nio/file/attribute/PosixFileAttributes": {
		supers:  "java/nio/file/attribute/BasicFileAttributes",
		methods: "group() owner() permissions()",
	},
	"java/nio/file/attribute/UserDefinedFileAttributeView": {
		supers:  "java/nio/file/attribute/FileAttributeView",
		methods: "delete(Ljava/lang/String;) list() name() read(Ljava/lang/String;Ljava/nio/ByteBuffer;) size(Ljava/lang/String;) write(Ljava/lang/String;Ljava/nio/ByteBuffer;)",
	},
	"java/nio/file/attribute/UserPrincipal": {
		supers: "java/security/Principal",
	},
	"java/nio/file/attribute/UserPrincipalLookupService": {
		methods: "lookupPrincipalByGroupName(Ljava/lang/String;) lookupPrincipalByName(Ljava/lang/String;)",
	},
	"java/nio/file/attribute/UserPrincipalNotFoundException": {
		supers:  "java/io/IOException",
		methods: "getName()",
	},
	"java/nio/file/spi/FileSystemProvider": {
		methods: "checkAccess(Ljava/nio/file/Path;[Ljava/nio/file/AccessMode;) copy(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;) createDirectory(Ljava/nio/file/Path;[Ljava/nio/file/attribute/FileAttribute;) createLink(Ljava/nio/file/Path;Ljava/nio/file/Path;) createSymbolicLink(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/attribute/FileAttribute;) delete(Ljava/nio/file/Path;) deleteIfExists(Ljava/nio/file/Path;) exists(Ljava/nio/file/Path;[Ljava/nio/file/LinkOption;) getFileAttributeView(Ljava/nio/file/Path;Ljava/lang/Class;[Ljava/nio/file/LinkOption;) getFileStore(Ljava/nio/file/Path;) getFileSystem(Ljava/net/URI;) getPath(Ljava/net/URI;) getScheme() isHidden(Ljava/nio/file/Path;) isSameFile(Ljava/nio/file/Path;Ljava/nio/file/Path;) move(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;) newAsynchronousFileChannel(Ljava/nio/file/Path;Ljava/util/Set;Ljava/util/concurrent/ExecutorService;[Ljava/nio/file/attribute/FileAttribute;) newByteChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;) newDirectoryStream(Ljava/nio/file/Path;Ljava/nio/file/DirectoryStream$Filter;) newFileChannel(Ljava/nio/file/Path;Ljava/util/Set;[Ljava/nio/file/attribute/FileAttribute;) newFileSystem(Ljava/net/URI;Ljava/util/Map;) newFileSystem(Ljava/nio/file/Path;Ljava/util/Map;) newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;) newOutputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;) readAttributes(Ljava/nio/file/Path;Ljava/lang/Class;[Ljava/nio/file/LinkOption;) readAttributes(Ljava/nio/file/Path;Ljava/lang/String;[Ljava/nio/file/LinkOption;) readAttributesIfExists(Ljava/nio/file/Path;Ljava/lang/Class;[Ljava/nio/file/LinkOption;) readSymbolicLink(Ljava/nio/file/Path;) setAttribute(Ljava/nio/file/Path;Ljava/lang/String;Ljava/lang/Object;[Ljava/nio/file/LinkOption;)",
	},
	"java/nio/file/spi/FileTypeDetector": {
		methods: "probeContentType(Ljava/nio/file/Path;)",
	},
	"java/security/AccessControlException": {
		supers:  "java/lang/SecurityException",
		methods: "getPermission()",
	},
	"java/security/AlgorithmConstraints": {
		methods: "permits(Ljava/util/Set;Ljava/lang/String;Ljava/security/AlgorithmParameters;) permits(Ljava/util/Set;Ljava/lang/String;Ljava/security/Key;Ljava/security/AlgorithmParameters;) permits(Ljava/util/Set;Ljava/security/Key;)",
	},
	"java/security/AlgorithmParameterGenerator": {},
	"java/security/AlgorithmParameterGeneratorSpi": {
		methods: "engineGenerateParameters() engineInit(ILjava/security/SecureRandom;) engineInit(Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)",
	},
	"java/security/AlgorithmParameters": {},
	"java/security/AlgorithmParametersSpi": {
		methods: "engineGetEncoded() engineGetEncoded(Ljava/lang/String;) engineGetParameterSpec(Ljava/lang/Class;) engineInit(Ljava/security/spec/AlgorithmParameterSpec;) engineInit([B) engineInit([BLjava/lang/String;) engineToString()",
	},
	"java/security/AuthProvider": {
		supers:  "java/security/Provider",
		methods: "login(Ljavax/security/auth/Subject;Ljavax/security/auth/callback/CallbackHandler;) logout() setCallbackHandler(Ljavax/security/auth/callback/CallbackHandler;)",
	},
	"java/security/BasicPermission": {
		supers:  "java/security/Permission java/io/Serializable",
		methods: "equals(Ljava/lang/Object;) getActions() hashCode() implies(Ljava/security/Permission;) newPermissionCollection()",
	},
	"java/security/Certificate": {
		methods: "decode(Ljava/io/InputStream;) encode(Ljava/io/OutputStream;) getFormat() getGuarantor() getPrincipal() getPublicKey() toString(Z)",
	},
	"java/security/CodeSource": {
		supers:  "java/io/Serializable",
		methods: "equals(Ljava/lang/Object;) hashCode() implies(Ljava/security/CodeSource;) toString()",
	},
	"java/security/DigestException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/DigestInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "getMessageDigest() on(Z) read() read([BII) setMessageDigest(Ljava/security/MessageDigest;) toString()",
	},
	"java/security/DigestOutputStream": {
		supers:  "java/io/FilterOutputStream",
		methods: "getMessageDigest() on(Z) setMessageDigest(Ljava/security/MessageDigest;) toString() write(I) write([BII)",
	},
	"java/security/DomainCombiner": {
		methods: "combine([Ljava/security/ProtectionDomain;[Ljava/security/ProtectionDomain;)",
	},
	"java/security/DrbgParameters": {},
	"java/security/GeneralSecurityException": {
		supers: "java/lang/Exception",
	},
	"java/security/Guard": {
		methods: "checkGuard(Ljava/lang/Object;)",
	},
	"java/security/GuardedObject": {
		supers:  "java/io/Serializable",
		methods: "getObject()",
	},
	"java/security/Identity": {
		supers:  "java/security/Principal java/io/Serializable",
		methods: "addCertificate(Ljava/security/Certificate;) certificates() getInfo() getPublicKey() hashCode() identityEquals(Ljava/security/Identity;) removeCertificate(Ljava/security/Certificate;) setInfo(Ljava/lang/String;) setPublicKey(Ljava/security/PublicKey;) toString() toString(Z)",
	},
	"java/security/IdentityScope": {
		supers:  "java/security/Identity",
		methods: "addIdentity(Ljava/security/Identity;) getIdentity(Ljava/lang/String;) getIdentity(Ljava/security/Principal;) getIdentity(Ljava/security/PublicKey;) identities() removeIdentity(Ljava/security/Identity;) size() toString()",
	},
	"java/security/InvalidAlgorithmParameterException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/InvalidKeyException": {
		supers: "java/security/KeyException",
	},
	"java/security/InvalidParameterException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/security/Key": {
		supers:  "java/io/Serializable",
		methods: "getAlgorithm() getEncoded() getFormat()",
	},
	"java/security/KeyException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/KeyFactory": {},
	"java/security/KeyFactorySpi": {
		methods: "engineGeneratePrivate(Ljava/security/spec/KeySpec;) engineGeneratePublic(Ljava/security/spec/KeySpec;) engineGetKeySpec(Ljava/security/Key;Ljava/lang/Class;) engineTranslateKey(Ljava/security/Key;)",
	},
	"java/security/KeyManagementException": {
		supers: "java/security/KeyException",
	},
	"java/security/KeyPairGenerator": {
		supers:  "java/security/KeyPairGeneratorSpi",
		methods: "generateKeyPair() getAlgorithm() initialize(I) initialize(ILjava/security/SecureRandom;) initialize(Ljava/security/spec/AlgorithmParameterSpec;) initialize(Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)",
	},
	"java/security/KeyPairGeneratorSpi": {
		methods: "generateKeyPair() initialize(ILjava/security/SecureRandom;) initialize(Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)",
	},
	"java/security/KeyRep": {
		supers:  "java/io/Serializable",
		methods: "readResolve()",
	},
	"java/security/KeyStore": {},
	"java/security/KeyStore$Builder": {
		methods: "getKeyStore() getProtectionParameter(Ljava/lang/String;)",
	},
	"java/security/KeyStore$CallbackHandlerProtection": {
		supers:  "java/security/KeyStore$ProtectionParameter",
		methods: "getCallbackHandler()",
	},
	"java/security/KeyStore$Entry": {
		methods: "getAttributes()",
	},
	"java/security/KeyStore$Entry$Attribute": {
		methods: "getName() getValue()",
	},
	"java/security/KeyStore$LoadStoreParameter": {
		methods: "getProtectionParameter()",
	},
	"java/security/KeyStore$PasswordProtection": {
		supers:  "java/security/KeyStore$ProtectionParameter javax/security/auth/Destroyable",
		methods: "destroy() getPassword() getProtectionAlgorithm() getProtectionParameters() isDestroyed()",
	},
	"java/security/KeyStore$ProtectionParameter": {},
	"java/security/KeyStoreException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/KeyStoreSpi": {
		methods: "engineAliases() engineContainsAlias(Ljava/lang/String;) engineDeleteEntry(Ljava/lang/String;) engineEntryInstanceOf(Ljava/lang/String;Ljava/lang/Class;) engineGetAttributes(Ljava/lang/String;) engineGetCertificate(Ljava/lang/String;) engineGetCertificateAlias(Ljava/security/cert/Certificate;) engineGetCertificateChain(Ljava/lang/String;) engineGetCreationDate(Ljava/lang/String;) engineGetEntry(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;) engineGetKey(Ljava/lang/String;[C) engineIsCertificateEntry(Ljava/lang/String;) engineIsKeyEntry(Ljava/lang/String;) engineLoad(Ljava/io/InputStream;[C) engineLoad(Ljava/security/KeyStore$LoadStoreParameter;) engineProbe(Ljava/io/InputStream;) engineSetCertificateEntry(Ljava/lang/String;Ljava/security/cert/Certificate;) engineSetEntry(Ljava/lang/String;Ljava/security/KeyStore$Entry;Ljava/security/KeyStore$ProtectionParameter;) engineSetKeyEntry(Ljava/lang/String;Ljava/security/Key;[C[Ljava/security/cert/Certificate;) engineSetKeyEntry(Ljava/lang/String;[B[Ljava/security/cert/Certificate;) engineSize() engineStore(Ljava/io/OutputStream;[C) engineStore(Ljava/security/KeyStore$LoadStoreParameter;)",
	},
	"java/security/MessageDigest": {
		supers:  "java/security/MessageDigestSpi",
		methods: "clone() digest() digest([B) digest([BII) reset() toString() update(B) update([B) update([BII)",
	},
	"java/security/MessageDigestSpi": {
		methods: "clone() engineDigest() engineDigest([BII) engineGetDigestLength() engineReset() engineUpdate(B) engineUpdate(Ljava/nio/ByteBuffer;) engineUpdate([BII)",
	},
	"java/security/NoSuchAlgorithmException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/NoSuchProviderException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/Permission": {
		supers:  "java/security/Guard java/io/Serializable",
		methods: "checkGuard(Ljava/lang/Object;) equals(Ljava/lang/Object;) getActions() hashCode() implies(Ljava/security/Permission;) newPermissionCollection() toString()",
	},
	"java/security/PermissionCollection": {
		supers:  "java/io/Serializable",
		methods: "add(Ljava/security/Permission;) elements() elementsAsStream() implies(Ljava/security/Permission;) isReadOnly() setReadOnly() toString()",
	},
	"java/security/Policy": {
		methods: "getParameters() getPermissions(Ljava/security/CodeSource;) getPermissions(Ljava/security/ProtectionDomain;) getProvider() getType() implies(Ljava/security/ProtectionDomain;Ljava/security/Permission;) refresh()",
	},
	"java/security/Policy$Parameters": {},
	"java/security/PolicySpi": {
		methods: "engineGetPermissions(Ljava/security/CodeSource;) engineGetPermissions(Ljava/security/ProtectionDomain;) engineImplies(Ljava/security/ProtectionDomain;Ljava/security/Permission;) engineRefresh()",
	},
	"java/security/Principal": {
		methods: "equals(Ljava/lang/Object;) getName() hashCode() implies(Ljavax/security/auth/Subject;) toString()",
	},
	"java/security/PrivateKey": {
		supers: "java/security/Key javax/security/auth/Destroyable",
	},
	"java/security/PrivilegedAction": {
		methods: "run()",
	},
	"java/security/PrivilegedActionException": {
		supers:  "java/lang/Exception",
		methods: "getException() toString()",
	},
	"java/security/PrivilegedExceptionAction": {
		methods: "run()",
	},
	"java/security/ProtectionDomain": {
		methods: "implies(Ljava/security/Permission;) toString()",
	},
	"java/security/Provider": {
		supers:  "java/util/Properties",
		methods: "clear() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) configure(Ljava/lang/String;) elements() entrySet() forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getInfo() getName() getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) getProperty(Ljava/lang/String;) getService(Ljava/lang/String;Ljava/lang/String;) getServices() getVersion() getVersionStr() isConfigured() keySet() keys() load(Ljava/io/InputStream;) merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) putService(Ljava/security/Provider$Service;) remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) removeService(Ljava/security/Provider$Service;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) toString() values()",
	},
	"java/security/Provider$Service": {
		methods: "newInstance(Ljava/lang/Object;) supportsParameter(Ljava/lang/Object;) toString()",
	},
	"java/security/ProviderException": {
		supers: "java/lang/RuntimeException",
	},
	"java/security/PublicKey": {
		supers: "java/security/Key",
	},
	"java/security/SecureClassLoader": {
		supers:  "java/lang/ClassLoader",
		methods: "getPermissions(Ljava/security/CodeSource;)",
	},
	"java/security/SecureRandom": {
		supers:  "java/util/Random",
		methods: "generateSeed(I) getAlgorithm() getParameters() nextBytes([B) nextBytes([BLjava/security/SecureRandomParameters;) reseed() reseed(Ljava/security/SecureRandomParameters;) setSeed(J) setSeed([B) toString()",
	},
	"java/security/SecureRandomParameters": {},
	"java/security/SecureRandomSpi": {
		supers:  "java/io/Serializable",
		methods: "engineGenerateSeed(I) engineGetParameters() engineNextBytes([B) engineNextBytes([BLjava/security/SecureRandomParameters;) engineReseed(Ljava/security/SecureRandomParameters;) engineSetSeed([B) toString()",
	},
	"java/security/Signature": {
		supers:  "java/security/SignatureSpi",
		methods: "clone() toString()",
	},
	"java/security/SignatureException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/SignatureSpi": {
		methods: "clone() engineGetParameter(Ljava/lang/String;) engineGetParameters() engineInitSign(Ljava/security/PrivateKey;) engineInitSign(Ljava/security/PrivateKey;Ljava/security/SecureRandom;) engineInitVerify(Ljava/security/PublicKey;) engineSetParameter(Ljava/lang/String;Ljava/lang/Object;) engineSetParameter(Ljava/security/spec/AlgorithmParameterSpec;) engineSign() engineSign([BII) engineUpdate(B) engineUpdate(Ljava/nio/ByteBuffer;) engineUpdate([BII) engineVerify([B) engineVerify([BII)",
	},
	"java/security/Signer": {
		supers:  "java/security/Identity",
		methods: "getPrivateKey() toString()",
	},
	"java/security/URIParameter": {
		supers:  "java/security/Policy$Parameters javax/security/auth/login/Configuration$Parameters",
		methods: "getURI()",
	},
	"java/security/UnrecoverableEntryException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/UnrecoverableKeyException": {
		supers: "java/security/UnrecoverableEntryException",
	},
	"java/security/cert/CRL": {
		methods: "isRevoked(Ljava/security/cert/Certificate;) toString()",
	},
	"java/security/cert/CRLException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/cert/CRLSelector": {
		supers:  "java/lang/Cloneable",
		methods: "clone() match(Ljava/security/cert/CRL;)",
	},
	"java/security/cert/CertPath": {
		supers:  "java/io/Serializable",
		methods: "equals(Ljava/lang/Object;) getCertificates() getEncoded() getEncoded(Ljava/lang/String;) getEncodings() getType() hashCode() toString() writeReplace()",
	},
	"java/security/cert/CertPath$CertPathRep": {
		supers:  "java/io/Serializable",
		methods: "readResolve()",
	},
	"java/security/cert/CertPathBuilder": {},
	"java/security/cert/CertPathBuilderException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/cert/CertPathBuilderResult": {
		supers:  "java/lang/Cloneable",
		methods: "clone() getCertPath()",
	},
	"java/security/cert/CertPathBuilderSpi": {
		methods: "engineBuild(Ljava/security/cert/CertPathParameters;) engineGetRevocationChecker()",
	},
	"java/security/cert/CertPathChecker": {
		methods: "check(Ljava/security/cert/Certificate;) init(Z) isForwardCheckingSupported()",
	},
	"java/security/cert/CertPathParameters": {
		supers:  "java/lang/Cloneable",
		methods: "clone()",
	},
	"java/security/cert/CertPathValidator": {},
	"java/security/cert/CertPathValidatorException": {
		supers:  "java/security/GeneralSecurityException",
		methods: "getCertPath() getIndex() getReason()",
	},
	"java/security/cert/CertPathValidatorException$Reason": {
		supers: "java/io/Serializable",
	},
	"java/security/cert/CertPathValidatorResult": {
		supers:  "java/lang/Cloneable",
		methods: "clone()",
	},
	"java/security/cert/CertPathValidatorSpi": {
		methods: "engineGetRevocationChecker() engineValidate(Ljava/security/cert/CertPath;Ljava/security/cert/CertPathParameters;)",
	},
	"java/security/cert/CertSelector": {
		supers:  "java/lang/Cloneable",
		methods: "clone() match(Ljava/security/cert/Certificate;)",
	},
	"java/security/cert/CertStore": {},
	"java/security/cert/CertStoreException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/cert/CertStoreParameters": {
		supers:  "java/lang/Cloneable",
		methods: "clone()",
	},
	"java/security/cert/CertStoreSpi": {
		methods: "engineGetCRLs(Ljava/security/cert/CRLSelector;) engineGetCertificates(Ljava/security/cert/CertSelector;)",
	},
	"java/security/cert/Certificate": {
		supers:  "java/io/Serializable",
		methods: "equals(Ljava/lang/Object;) getEncoded() getPublicKey() hashCode() toString() verify(Ljava/security/PublicKey;) verify(Ljava/security/PublicKey;Ljava/lang/String;) verify(Ljava/security/PublicKey;Ljava/security/Provider;) writeReplace()",
	},
	"java/security/cert/Certificate$CertificateRep": {
		supers:  "java/io/Serializable",
		methods: "readResolve()",
	},
	"java/security/cert/CertificateEncodingException": {
		supers: "java/security/cert/CertificateException",
	},
	"java/security/cert/CertificateException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/cert/CertificateExpiredException": {
		supers: "java/security/cert/CertificateException",
	},
	"java/security/cert/CertificateFactory": {},
	"java/security/cert/CertificateFactorySpi": {
		methods: "engineGenerateCRL(Ljava/io/InputStream;) engineGenerateCRLs(Ljava/io/InputStream;) engineGenerateCertPath(Ljava/io/InputStream;) engineGenerateCertPath(Ljava/io/InputStream;Ljava/lang/String;) engineGenerateCertPath(Ljava/util/List;) engineGenerateCertificate(Ljava/io/InputStream;) engineGenerateCertificates(Ljava/io/InputStream;) engineGetCertPathEncodings()",
	},
	"java/security/cert/CertificateNotYetValidException": {
		supers: "java/security/cert/CertificateException",
	},
	"java/security/cert/CertificateParsingException": {
		supers: "java/security/cert/CertificateException",
	},
	"java/security/cert/CertificateRevokedException": {
		supers:  "java/security/cert/CertificateException",
		methods: "getAuthorityName() getExtensions() getInvalidityDate() getMessage() getRevocationDate() getRevocationReason()",
	},
	"java/security/cert/CollectionCertStoreParameters": {
		supers:  "java/security/cert/CertStoreParameters",
		methods: "clone() getCollection() toString()",
	},
	"java/security/cert/Extension": {
		methods: "encode(Ljava/io/OutputStream;) getId() getValue() isCritical()",
	},
	"java/security/cert/LDAPCertStoreParameters": {
		supers:  "java/security/cert/CertStoreParameters",
		methods: "clone() getPort() getServerName() toString()",
	},
	"java/security/cert/PKIXBuilderParameters": {
		supers:  "java/security/cert/PKIXParameters",
		methods: "getMaxPathLength() setMaxPathLength(I) toString()",
	},
	"java/security/cert/PKIXCertPathBuilderResult": {
		supers:  "java/security/cert/PKIXCertPathValidatorResult java/security/cert/CertPathBuilderResult",
		methods: "getCertPath() toString()",
	},
	"java/security/cert/PKIXCertPathChecker": {
		supers:  "java/security/cert/CertPathChecker java/lang/Cloneable",
		methods: "check(Ljava/security/cert/Certificate;) check(Ljava/security/cert/Certificate;Ljava/util/Collection;) clone() getSupportedExtensions() init(Z) isForwardCheckingSupported()",
	},
	"java/security/cert/PKIXCertPathValidatorResult": {
		supers:  "java/security/cert/CertPathValidatorResult",
		methods: "clone() getPolicyTree() getPublicKey() getTrustAnchor() toString()",
	},
	"java/security/cert/PKIXParameters": {
		supers:  "java/security/cert/CertPathParameters",
		methods: "addCertPathChecker(Ljava/security/cert/PKIXCertPathChecker;) addCertStore(Ljava/security/cert/CertStore;) clone() getCertPathCheckers() getCertStores() getDate() getInitialPolicies() getPolicyQualifiersRejected() getSigProvider() getTargetCertConstraints() getTrustAnchors() isAnyPolicyInhibited() isExplicitPolicyRequired() isPolicyMappingInhibited() isRevocationEnabled() setAnyPolicyInhibited(Z) setCertPathCheckers(Ljava/util/List;) setCertStores(Ljava/util/List;) setDate(Ljava/util/Date;) setExplicitPolicyRequired(Z) setInitialPolicies(Ljava/util/Set;) setPolicyMappingInhibited(Z) setPolicyQualifiersRejected(Z) setRevocationEnabled(Z) setSigProvider(Ljava/lang/String;) setTargetCertConstraints(Ljava/security/cert/CertSelector;) setTrustAnchors(Ljava/util/Set;) toString()",
	},
	"java/security/cert/PKIXRevocationChecker": {
		supers:  "java/security/cert/PKIXCertPathChecker",
		methods: "clone() getOcspExtensions() getOcspResponder() getOcspResponderCert() getOcspResponses() getOptions() getSoftFailExceptions() setOcspExtensions(Ljava/util/List;) setOcspResponder(Ljava/net/URI;) setOcspResponderCert(Ljava/security/cert/X509Certificate;) setOcspResponses(Ljava/util/Map;) setOptions(Ljava/util/Set;)",
	},
	"java/security/cert/PolicyNode": {
		methods: "getChildren() getDepth() getExpectedPolicies() getParent() getPolicyQualifiers() getValidPolicy() isCritical()",
	},
	"java/security/cert/PolicyQualifierInfo": {
		methods: "toString()",
	},
	"java/security/cert/TrustAnchor": {
		methods: "toString()",
	},
	"java/security/cert/X509CRL": {
		supers:  "java/security/cert/CRL java/security/cert/X509Extension",
		methods: "equals(Ljava/lang/Object;) getEncoded() getIssuerDN() getIssuerX500Principal() getNextUpdate() getRevokedCertificate(Ljava/math/BigInteger;) getRevokedCertificate(Ljava/security/cert/X509Certificate;) getRevokedCertificates() getSigAlgName() getSigAlgOID() getSigAlgParams() getSignature() getTBSCertList() getThisUpdate() getVersion() hashCode() verify(Ljava/security/PublicKey;) verify(Ljava/security/PublicKey;Ljava/lang/String;) verify(Ljava/security/PublicKey;Ljava/security/Provider;)",
	},
	"java/security/cert/X509CRLEntry": {
		supers:  "java/security/cert/X509Extension",
		methods: "equals(Ljava/lang/Object;) getCertificateIssuer() getEncoded() getRevocationDate() getRevocationReason() getSerialNumber() hasExtensions() hashCode() toString()",
	},
	"java/security/cert/X509CRLSelector": {
		supers:  "java/security/cert/CRLSelector",
		methods: "addIssuer(Ljavax/security/auth/x500/X500Principal;) addIssuerName(Ljava/lang/String;) addIssuerName([B) clone() getCertificateChecking() getDateAndTime() getIssuerNames() getIssuers() getMaxCRL() getMinCRL() match(Ljava/security/cert/CRL;) setCertificateChecking(Ljava/security/cert/X509Certificate;) setDateAndTime(Ljava/util/Date;) setIssuerNames(Ljava/util/Collection;) setIssuers(Ljava/util/Collection;) setMaxCRLNumber(Ljava/math/BigInteger;) setMinCRLNumber(Ljava/math/BigInteger;) toString()",
	},
	"java/security/cert/X509CertSelector": {
		supers:  "java/security/cert/CertSelector",
		methods: "addPathToName(ILjava/lang/String;) addPathToName(I[B) addSubjectAlternativeName(ILjava/lang/String;) addSubjectAlternativeName(I[B) clone() getAuthorityKeyIdentifier() getBasicConstraints() getCertificate() getCertificateValid() getExtendedKeyUsage() getIssuer() getIssuerAsBytes() getIssuerAsString() getKeyUsage() getMatchAllSubjectAltNames() getNameConstraints() getPathToNames() getPolicy() getPrivateKeyValid() getSerialNumber() getSubject() getSubjectAlternativeNames() getSubjectAsBytes() getSubjectAsString() getSubjectKeyIdentifier() getSubjectPublicKey() getSubjectPublicKeyAlgID() match(Ljava/security/cert/Certificate;) setAuthorityKeyIdentifier([B) setBasicConstraints(I) setCertificate(Ljava/security/cert/X509Certificate;) setCertificateValid(Ljava/util/Date;) setExtendedKeyUsage(Ljava/util/Set;) setIssuer(Ljava/lang/String;) setIssuer(Ljavax/security/auth/x500/X500Principal;) setIssuer([B) setKeyUsage([Z) setMatchAllSubjectAltNames(Z) setNameConstraints([B) setPathToNames(Ljava/util/Collection;) setPolicy(Ljava/util/Set;) setPrivateKeyValid(Ljava/util/Date;) setSerialNumber(Ljava/math/BigInteger;) setSubject(Ljava/lang/String;) setSubject(Ljavax/security/auth/x500/X500Principal;) setSubject([B) setSubjectAlternativeNames(Ljava/util/Collection;) setSubjectKeyIdentifier([B) setSubjectPublicKey(Ljava/security/PublicKey;) setSubjectPublicKey([B) setSubjectPublicKeyAlgID(Ljava/lang/String;) toString()",
	},
	"java/security/cert/X509Certificate": {
		supers:  "java/security/cert/Certificate java/security/cert/X509Extension",
		methods: "checkValidity() checkValidity(Ljava/util/Date;) getBasicConstraints() getExtendedKeyUsage() getIssuerAlternativeNames() getIssuerDN() getIssuerUniqueID() getIssuerX500Principal() getKeyUsage() getNotAfter() getNotBefore() getSerialNumber() getSigAlgName() getSigAlgOID() getSigAlgParams() getSignature() getSubjectAlternativeNames() getSubjectDN() getSubjectUniqueID() getSubjectX500Principal() getTBSCertificate() getVersion() verify(Ljava/security/PublicKey;Ljava/security/Provider;)",
	},
	"java/security/cert/X509Extension": {
		methods: "getCriticalExtensionOIDs() getExtensionValue(Ljava/lang/String;) getNonCriticalExtensionOIDs() hasUnsupportedCriticalExtension()",
	},
	"java/security/interfaces/DSAKey": {
		methods: "getParams()",
	},
	"java/security/interfaces/DSAKeyPairGenerator": {
		methods: "initialize(IZLjava/security/SecureRandom;) initialize(Ljava/security/interfaces/DSAParams;Ljava/security/SecureRandom;)",
	},
	"java/security/interfaces/DSAParams": {
		methods: "getG() getP() getQ()",
	},
	"java/security/interfaces/DSAPrivateKey": {
		supers:  "java/security/interfaces/DSAKey java/security/PrivateKey",
		methods: "getX()",
	},
	"java/security/interfaces/DSAPublicKey": {
		supers:  "java/security/interfaces/DSAKey java/security/PublicKey",
		methods: "getY()",
	},
	"java/security/interfaces/ECKey": {
		methods: "getParams()",
	},
	"java/security/interfaces/ECPrivateKey": {
		supers:  "java/security/PrivateKey java/security/interfaces/ECKey",
		methods: "getS()",
	},
	"java/security/interfaces/ECPublicKey": {
		supers:  "java/security/PublicKey java/security/interfaces/ECKey",
		methods: "getW()",
	},
	"java/security/interfaces/EdECKey": {
		methods: "getParams()",
	},
	"java/security/interfaces/EdECPrivateKey": {
		supers:  "java/security/interfaces/EdECKey java/security/PrivateKey",
		methods: "getBytes()",
	},
	"java/security/interfaces/EdECPublicKey": {
		supers:  "java/security/interfaces/EdECKey java/security/PublicKey",
		methods: "getPoint()",
	},
	"java/security/interfaces/RSAKey": {
		methods: "getModulus() getParams()",
	},
	"java/security/interfaces/RSAMultiPrimePrivateCrtKey": {
		supers:  "java/security/interfaces/RSAPrivateKey",
		methods: "getCrtCoefficient() getOtherPrimeInfo() getPrimeExponentP() getPrimeExponentQ() getPrimeP() getPrimeQ() getPublicExponent()",
	},
	"java/security/interfaces/RSAPrivateCrtKey": {
		supers:  "java/security/interfaces/RSAPrivateKey",
		methods: "getCrtCoefficient() getPrimeExponentP() getPrimeExponentQ() getPrimeP() getPrimeQ() getPublicExponent()",
	},
	"java/security/interfaces/RSAPrivateKey": {
		supers:  "java/security/PrivateKey java/security/interfaces/RSAKey",
		methods: "getPrivateExponent()",
	},
	"java/security/interfaces/RSAPublicKey": {
		supers:  "java/security/PublicKey java/security/interfaces/RSAKey",
		methods: "getPublicExponent()",
	},
	"java/security/interfaces/XECKey": {
		methods: "getParams()",
	},
	"java/security/interfaces/XECPrivateKey": {
		supers:  "java/security/interfaces/XECKey java/security/PrivateKey",
		methods: "getScalar()",
	},
	"java/security/interfaces/XECPublicKey": {
		supers:  "java/security/interfaces/XECKey java/security/PublicKey",
		methods: "getU()",
	},
	"java/security/spec/AlgorithmParameterSpec": {},
	"java/security/spec/DSAParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec java/security/interfaces/DSAParams",
		methods: "getG() getP() getQ()",
	},
	"java/security/spec/DSAPrivateKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getG() getP() getQ() getX()",
	},
	"java/security/spec/DSAPublicKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getG() getP() getQ() getY()",
	},
	"java/security/spec/ECField": {
		methods: "getFieldSize()",
	},
	"java/security/spec/ECFieldF2m": {
		supers:  "java/security/spec/ECField",
		methods: "equals(Ljava/lang/Object;) getFieldSize() getM() getMidTermsOfReductionPolynomial() getReductionPolynomial() hashCode()",
	},
	"java/security/spec/ECFieldFp": {
		supers:  "java/security/spec/ECField",
		methods: "equals(Ljava/lang/Object;) getFieldSize() getP() hashCode()",
	},
	"java/security/spec/ECGenParameterSpec": {
		supers: "java/security/spec/NamedParameterSpec",
	},
	"java/security/spec/ECParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getCofactor() getCurve() getGenerator() getOrder()",
	},
	"java/security/spec/ECPoint": {
		methods: "equals(Ljava/lang/Object;) getAffineX() getAffineY() hashCode()",
	},
	"java/security/spec/ECPrivateKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getParams() getS()",
	},
	"java/security/spec/ECPublicKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getParams() getW()",
	},
	"java/security/spec/EdDSAParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getContext() isPrehash()",
	},
	"java/security/spec/EllipticCurve": {
		methods: "equals(Ljava/lang/Object;) getA() getB() getField() getSeed() hashCode()",
	},
	"java/security/spec/EncodedKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getAlgorithm() getEncoded() getFormat()",
	},
	"java/security/spec/InvalidKeySpecException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/spec/InvalidParameterSpecException": {
		supers: "java/security/GeneralSecurityException",
	},
	"java/security/spec/KeySpec": {},
	"java/security/spec/MGF1ParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getDigestAlgorithm() toString()",
	},
	"java/security/spec/NamedParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getName()",
	},
	"java/security/spec/PKCS8EncodedKeySpec": {
		supers:  "java/security/spec/EncodedKeySpec",
		methods: "getEncoded()",
	},
	"java/security/spec/PSSParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getDigestAlgorithm() getMGFAlgorithm() getMGFParameters() getSaltLength() getTrailerField() toString()",
	},
	"java/security/spec/RSAKeyGenParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getKeyParams() getKeysize() getPublicExponent()",
	},
	"java/security/spec/RSAMultiPrimePrivateCrtKeySpec": {
		supers:  "java/security/spec/RSAPrivateKeySpec",
		methods: "getCrtCoefficient() getOtherPrimeInfo() getPrimeExponentP() getPrimeExponentQ() getPrimeP() getPrimeQ() getPublicExponent()",
	},
	"java/security/spec/RSAOtherPrimeInfo": {},
	"java/security/spec/RSAPrivateCrtKeySpec": {
		supers:  "java/security/spec/RSAPrivateKeySpec",
		methods: "getCrtCoefficient() getPrimeExponentP() getPrimeExponentQ() getPrimeP() getPrimeQ() getPublicExponent()",
	},
	"java/security/spec/RSAPrivateKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getModulus() getParams() getPrivateExponent()",
	},
	"java/security/spec/RSAPublicKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getModulus() getParams() getPublicExponent()",
	},
	"java/security/spec/X509EncodedKeySpec": {
		supers:  "java/security/spec/EncodedKeySpec",
		methods: "getEncoded()",
	},
	"java/security/spec/XECPrivateKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getParams() getScalar()",
	},
	"java/security/spec/XECPublicKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getParams() getU()",
	},
	"java/text/Annotation": {
		methods: "getValue() toString()",
	},
	"java/text/AttributedCharacterIterator": {
		supers:  "java/text/CharacterIterator",
		methods: "getAllAttributeKeys() getAttribute(Ljava/text/AttributedCharacterIterator$Attribute;) getAttributes() getRunLimit() getRunLimit(Ljava/text/AttributedCharacterIterator$Attribute;) getRunLimit(Ljava/util/Set;) getRunStart() getRunStart(Ljava/text/AttributedCharacterIterator$Attribute;) getRunStart(Ljava/util/Set;)",
	},
	"java/text/AttributedCharacterIterator$Attribute": {
		supers:  "java/io/Serializable",
		methods: "getName() readResolve() toString()",
	},
	"java/text/AttributedString": {
		methods: "addAttribute(Ljava/text/AttributedCharacterIterator$Attribute;Ljava/lang/Object;) addAttribute(Ljava/text/AttributedCharacterIterator$Attribute;Ljava/lang/Object;II) addAttributes(Ljava/util/Map;II) getIterator() getIterator([Ljava/text/AttributedCharacterIterator$Attribute;) getIterator([Ljava/text/AttributedCharacterIterator$Attribute;II)",
	},
	"java/text/BreakIterator": {
		supers:  "java/lang/Cloneable",
		methods: "clone() current() first() following(I) getText() isBoundary(I) last() next() next(I) preceding(I) previous() setText(Ljava/lang/String;) setText(Ljava/text/CharacterIterator;)",
	},
	"java/text/CharacterIterator": {
		supers:  "java/lang/Cloneable",
		methods: "clone() current() first() getBeginIndex() getEndIndex() getIndex() last() next() previous() setIndex(I)",
	},
	"java/text/ChoiceFormat": {
		supers:  "java/text/NumberFormat",
		methods: "applyPattern(Ljava/lang/String;) clone() equals(Ljava/lang/Object;) format(DLjava/lang/StringBuffer;Ljava/text/FieldPosition;) format(JLjava/lang/StringBuffer;Ljava/text/FieldPosition;) getFormats() getLimits() hashCode() parse(Ljava/lang/String;Ljava/text/ParsePosition;) setChoices([D[Ljava/lang/String;) toPattern()",
	},
	"java/text/CollationKey": {
		supers:  "java/lang/Comparable",
		methods: "compareTo(Ljava/lang/Object;) compareTo(Ljava/text/CollationKey;) getSourceString() toByteArray()",
	},
	"java/text/Collator": {
		supers:  "java/util/Comparator java/lang/Cloneable",
		methods: "clone() compare(Ljava/lang/Object;Ljava/lang/Object;) compare(Ljava/lang/String;Ljava/lang/String;) equals(Ljava/lang/Object;) equals(Ljava/lang/String;Ljava/lang/String;) getCollationKey(Ljava/lang/String;) getDecomposition() getStrength() hashCode() setDecomposition(I) setStrength(I)",
	},
	"java/text/DateFormat": {
		supers:  "java/text/Format",
		methods: "clone() equals(Ljava/lang/Object;) format(Ljava/util/Date;Ljava/lang/StringBuffer;Ljava/text/FieldPosition;) getCalendar() getNumberFormat() getTimeZone() hashCode() isLenient() parse(Ljava/lang/String;) parse(Ljava/lang/String;Ljava/text/ParsePosition;) parseObject(Ljava/lang/String;Ljava/text/ParsePosition;) setCalendar(Ljava/util/Calendar;) setLenient(Z) setNumberFormat(Ljava/text/NumberFormat;) setTimeZone(Ljava/util/TimeZone;)",
	},
	"java/text/DateFormat$Field": {
		supers:  "java/text/Format$Field",
		methods: "getCalendarField() readResolve()",
	},
	"java/text/DateFormatSymbols": {
		supers:  "java/io/Serializable java/lang/Cloneable",
		methods: "clone() equals(Ljava/lang/Object;) getAmPmStrings() getEras() getLocalPatternChars() getMonths() getShortMonths() getShortWeekdays() getWeekdays() getZoneStrings() hashCode() setAmPmStrings([Ljava/lang/String;) setEras([Ljava/lang/String;) setLocalPatternChars(Ljava/lang/String;) setMonths([Ljava/lang/String;) setShortMonths([Ljava/lang/String;) setShortWeekdays([Ljava/lang/String;) setWeekdays([Ljava/lang/String;) setZoneStrings([[Ljava/lang/String;)",
	},
	"java/text/DecimalFormat": {
		supers:  "java/text/NumberFormat",
		methods: "applyLocalizedPattern(Ljava/lang/String;) applyPattern(Ljava/lang/String;) clone() equals(Ljava/lang/Object;) format(DLjava/lang/StringBuffer;Ljava/text/FieldPosition;) format(JLjava/lang/StringBuffer;Ljava/text/FieldPosition;) formatToCharacterIterator(Ljava/lang/Object;) getCurrency() getDecimalFormatSymbols() getGroupingSize() getMaximumFractionDigits() getMaximumIntegerDigits() getMinimumFractionDigits() getMinimumIntegerDigits() getMultiplier() getNegativePrefix() getNegativeSuffix() getPositivePrefix() getPositiveSuffix() getRoundingMode() hashCode() isDecimalSeparatorAlwaysShown() isParseBigDecimal() parse(Ljava/lang/String;Ljava/text/ParsePosition;) setCurrency(Ljava/util/Currency;) setDecimalFormatSymbols(Ljava/text/DecimalFormatSymbols;) setDecimalSeparatorAlwaysShown(Z) setGroupingSize(I) setGroupingUsed(Z) setMaximumFractionDigits(I) setMaximumIntegerDigits(I) setMinimumFractionDigits(I) setMinimumIntegerDigits(I) setMultiplier(I) setNegativePrefix(Ljava/lang/String;) setNegativeSuffix(Ljava/lang/String;) setParseBigDecimal(Z) setPositivePrefix(Ljava/lang/String;) setPositiveSuffix(Ljava/lang/String;) setRoundingMode(Ljava/math/RoundingMode;) toLocalizedPattern() toPattern()",
	},
	"java/text/DecimalFormatSymbols": {
		supers:  "java/lang/Cloneable java/io/Serializable",
		methods: "clone() equals(Ljava/lang/Object;) getCurrency() getCurrencySymbol() getDecimalSeparator() getDigit() getExponentSeparator() getGroupingSeparator() getInfinity() getInternationalCurrencySymbol() getLocale() getMinusSign() getMonetaryDecimalSeparator() getMonetaryGroupingSeparator() getNaN() getPatternSeparator() getPerMill() getPercent() getZeroDigit() hashCode() setCurrency(Ljava/util/Currency;) setCurrencySymbol(Ljava/lang/String;) setDecimalSeparator(C) setDigit(C) setExponentSeparator(Ljava/lang/String;) setGroupingSeparator(C) setInfinity(Ljava/lang/String;) setInternationalCurrencySymbol(Ljava/lang/String;) setMinusSign(C) setMonetaryDecimalSeparator(C) setMonetaryGroupingSeparator(C) setNaN(Ljava/lang/String;) setPatternSeparator(C) setPerMill(C) setPercent(C) setZeroDigit(C)",
	},
	"java/text/FieldPosition": {
		methods: "equals(Ljava/lang/Object;) getBeginIndex() getEndIndex() getField() getFieldAttribute() hashCode() setBeginIndex(I) setEndIndex(I) toString()",
	},
	"java/text/Format": {
		supers:  "java/io/Serializable java/lang/Cloneable",
		methods: "clone() format(Ljava/lang/Object;Ljava/lang/StringBuffer;Ljava/text/FieldPosition;) formatToCharacterIterator(Ljava/lang/Object;) parseObject(Ljava/lang/String;) parseObject(Ljava/lang/String;Ljava/text/ParsePosition;)",
	},
	"java/text/Format$Field": {
		supers: "java/text/AttributedCharacterIterator$Attribute",
	},
	"java/text/MessageFormat": {
		supers:  "java/text/Format",
		methods: "applyPattern(Ljava/lang/String;) clone() equals(Ljava/lang/Object;) formatToCharacterIterator(Ljava/lang/Object;) getFormats() getFormatsByArgumentIndex() getLocale() hashCode() parse(Ljava/lang/String;) parse(Ljava/lang/String;Ljava/text/ParsePosition;) parseObject(Ljava/lang/String;Ljava/text/ParsePosition;) setFormat(ILjava/text/Format;) setFormatByArgumentIndex(ILjava/text/Format;) setFormats([Ljava/text/Format;) setFormatsByArgumentIndex([Ljava/text/Format;) setLocale(Ljava/util/Locale;) toPattern()",
	},
	"java/text/MessageFormat$Field": {
		supers:  "java/text/Format$Field",
		methods: "readResolve()",
	},
	"java/text/NumberFormat": {
		supers:  "java/text/Format",
		methods: "clone() equals(Ljava/lang/Object;) format(DLjava/lang/StringBuffer;Ljava/text/FieldPosition;) format(JLjava/lang/StringBuffer;Ljava/text/FieldPosition;) format(Ljava/lang/Object;Ljava/lang/StringBuffer;Ljava/text/FieldPosition;) getCurrency() getMaximumFractionDigits() getMaximumIntegerDigits() getMinimumFractionDigits() getMinimumIntegerDigits() getRoundingMode() hashCode() isGroupingUsed() isParseIntegerOnly() parse(Ljava/lang/String;) parse(Ljava/lang/String;Ljava/text/ParsePosition;) setCurrency(Ljava/util/Currency;) setGroupingUsed(Z) setMaximumFractionDigits(I) setMaximumIntegerDigits(I) setMinimumFractionDigits(I) setMinimumIntegerDigits(I) setParseIntegerOnly(Z) setRoundingMode(Ljava/math/RoundingMode;)",
	},
	"java/text/NumberFormat$Field": {
		supers:  "java/text/Format$Field",
		methods: "readResolve()",
	},
	"java/text/ParseException": {
		supers:  "java/lang/Exception",
		methods: "getErrorOffset()",
	},
	"java/text/ParsePosition": {
		methods: "equals(Ljava/lang/Object;) getErrorIndex() getIndex() hashCode() setErrorIndex(I) setIndex(I) toString()",
	},
	"java/text/RuleBasedCollator": {
		supers:  "java/text/Collator",
		methods: "clone() compare(Ljava/lang/String;Ljava/lang/String;) equals(Ljava/lang/Object;) getCollationElementIterator(Ljava/lang/String;) getCollationElementIterator(Ljava/text/CharacterIterator;) getCollationKey(Ljava/lang/String;) getRules() hashCode()",
	},
	"java/text/SimpleDateFormat": {
		supers:  "java/text/DateFormat",
		methods: "applyLocalizedPattern(Ljava/lang/String;) applyPattern(Ljava/lang/String;) clone() equals(Ljava/lang/Object;) format(Ljava/util/Date;Ljava/lang/StringBuffer;Ljava/text/FieldPosition;) formatToCharacterIterator(Ljava/lang/Object;) get2DigitYearStart() getDateFormatSymbols() hashCode() parse(Ljava/lang/String;Ljava/text/ParsePosition;) set2DigitYearStart(Ljava/util/Date;) setDateFormatSymbols(Ljava/text/DateFormatSymbols;) toLocalizedPattern() toPattern()",
	},
	"java/text/spi/BreakIteratorProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getCharacterInstance(Ljava/util/Locale;) getLineInstance(Ljava/util/Locale;) getSentenceInstance(Ljava/util/Locale;) getWordInstance(Ljava/util/Locale;)",
	},
	"java/text/spi/CollatorProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getInstance(Ljava/util/Locale;)",
	},
	"java/text/spi/DateFormatProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getDateInstance(ILjava/util/Locale;) getDateTimeInstance(IILjava/util/Locale;) getTimeInstance(ILjava/util/Locale;)",
	},
	"java/text/spi/DateFormatSymbolsProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getInstance(Ljava/util/Locale;)",
	},
	"java/text/spi/DecimalFormatSymbolsProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getInstance(Ljava/util/Locale;)",
	},
	"java/text/spi/NumberFormatProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getCompactNumberInstance(Ljava/util/Locale;Ljava/text/NumberFormat$Style;) getCurrencyInstance(Ljava/util/Locale;) getIntegerInstance(Ljava/util/Locale;) getNumberInstance(Ljava/util/Locale;) getPercentInstance(Ljava/util/Locale;)",
	},
	"java/time/Clock": {
		supers:  "java/time/InstantSource",
		methods: "equals(Ljava/lang/Object;) getZone() hashCode() instant() millis() withZone(Ljava/time/ZoneId;)",
	},
	"java/time/DateTimeException": {
		supers: "java/lang/RuntimeException",
	},
	"java/time/InstantSource": {
		methods: "instant() millis() withZone(Ljava/time/ZoneId;)",
	},
	"java/time/chrono/AbstractChronology": {
		supers:  "java/time/chrono/Chronology",
		methods: "compareTo(Ljava/lang/Object;) compareTo(Ljava/time/chrono/Chronology;) equals(Ljava/lang/Object;) hashCode() resolveDate(Ljava/util/Map;Ljava/time/format/ResolverStyle;) toString()",
	},
	"java/time/chrono/ChronoLocalDate": {
		supers:  "java/time/temporal/Temporal java/time/temporal/TemporalAdjuster java/lang/Comparable",
		methods: "adjustInto(Ljava/time/temporal/Temporal;) atTime(Ljava/time/LocalTime;) compareTo(Ljava/lang/Object;) compareTo(Ljava/time/chrono/ChronoLocalDate;) equals(Ljava/lang/Object;) format(Ljava/time/format/DateTimeFormatter;) getChronology() getEra() hashCode() isAfter(Ljava/time/chrono/ChronoLocalDate;) isBefore(Ljava/time/chrono/ChronoLocalDate;) isEqual(Ljava/time/chrono/ChronoLocalDate;) isLeapYear() isSupported(Ljava/time/temporal/TemporalField;) isSupported(Ljava/time/temporal/TemporalUnit;) lengthOfMonth() lengthOfYear() minus(JLjava/time/temporal/TemporalUnit;) minus(Ljava/time/temporal/TemporalAmount;) plus(JLjava/time/temporal/TemporalUnit;) plus(Ljava/time/temporal/TemporalAmount;) query(Ljava/time/temporal/TemporalQuery;) toEpochDay() toString() until(Ljava/time/chrono/ChronoLocalDate;) until(Ljava/time/temporal/Temporal;Ljava/time/temporal/TemporalUnit;) with(Ljava/time/temporal/TemporalAdjuster;) with(Ljava/time/temporal/TemporalField;J)",
	},
	"java/time/chrono/ChronoLocalDateTime": {
		supers:  "java/time/temporal/Temporal java/time/temporal/TemporalAdjuster java/lang/Comparable",
		methods: "adjustInto(Ljava/time/temporal/Temporal;) atZone(Ljava/time/ZoneId;) compareTo(Ljava/lang/Object;) compareTo(Ljava/time/chrono/ChronoLocalDateTime;) equals(Ljava/lang/Object;) format(Ljava/time/format/DateTimeFormatter;) getChronology() hashCode() isAfter(Ljava/time/chrono/ChronoLocalDateTime;) isBefore(Ljava/time/chrono/ChronoLocalDateTime;) isEqual(Ljava/time/chrono/ChronoLocalDateTime;) isSupported(Ljava/time/temporal/TemporalField;) isSupported(Ljava/time/temporal/TemporalUnit;) minus(JLjava/time/temporal/TemporalUnit;) minus(Ljava/time/temporal/TemporalAmount;) plus(JLjava/time/temporal/TemporalUnit;) plus(Ljava/time/temporal/TemporalAmount;) query(Ljava/time/temporal/TemporalQuery;) toEpochSecond(Ljava/time/ZoneOffset;) toInstant(Ljava/time/ZoneOffset;) toLocalDate() toLocalTime() toString() with(Ljava/time/temporal/TemporalAdjuster;) with(Ljava/time/temporal/TemporalField;J)",
	},
	"java/time/chrono/ChronoPeriod": {
		supers:  "java/time/temporal/TemporalAmount",
		methods: "addTo(Ljava/time/temporal/Temporal;) equals(Ljava/lang/Object;) get(Ljava/time/temporal/TemporalUnit;) getChronology() getUnits() hashCode() isNegative() isZero() minus(Ljava/time/temporal/TemporalAmount;) multipliedBy(I) negated() normalized() plus(Ljava/time/temporal/TemporalAmount;) subtractFrom(Ljava/time/temporal/Temporal;) toString()",
	},
	"java/time/chrono/ChronoZonedDateTime": {
		supers:  "java/time/temporal/Temporal java/lang/Comparable",
		methods: "compareTo(Ljava/lang/Object;) compareTo(Ljava/time/chrono/ChronoZonedDateTime;) equals(Ljava/lang/Object;) format(Ljava/time/format/DateTimeFormatter;) get(Ljava/time/temporal/TemporalField;) getChronology() getLong(Ljava/time/temporal/TemporalField;) getOffset() getZone() hashCode() isAfter(Ljava/time/chrono/ChronoZonedDateTime;) isBefore(Ljava/time/chrono/ChronoZonedDateTime;) isEqual(Ljava/time/chrono/ChronoZonedDateTime;) isSupported(Ljava/time/temporal/TemporalField;) isSupported(Ljava/time/temporal/TemporalUnit;) minus(JLjava/time/temporal/TemporalUnit;) minus(Ljava/time/temporal/TemporalAmount;) plus(JLjava/time/temporal/TemporalUnit;) plus(Ljava/time/temporal/TemporalAmount;) query(Ljava/time/temporal/TemporalQuery;) range(Ljava/time/temporal/TemporalField;) toEpochSecond() toInstant() toLocalDate() toLocalDateTime() toLocalTime() toString() with(Ljava/time/temporal/TemporalAdjuster;) with(Ljava/time/temporal/TemporalField;J) withEarlierOffsetAtOverlap() withLaterOffsetAtOverlap() withZoneSameInstant(Ljava/time/ZoneId;) withZoneSameLocal(Ljava/time/ZoneId;)",
	},
	"java/time/chrono/Chronology": {
		supers:  "java/lang/Comparable",
		methods: "compareTo(Ljava/lang/Object;) compareTo(Ljava/time/chrono/Chronology;) date(III) date(Ljava/time/chrono/Era;III) date(Ljava/time/temporal/TemporalAccessor;) dateEpochDay(J) dateNow() dateNow(Ljava/time/Clock;) dateNow(Ljava/time/ZoneId;) dateYearDay(II) dateYearDay(Ljava/time/chrono/Era;II) epochSecond(IIIIIILjava/time/ZoneOffset;) epochSecond(Ljava/time/chrono/Era;IIIIIILjava/time/ZoneOffset;) equals(Ljava/lang/Object;) eraOf(I) eras() getCalendarType() getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;) getId() hashCode() isIsoBased() isLeapYear(J) localDateTime(Ljava/time/temporal/TemporalAccessor;) period(III) prolepticYear(Ljava/time/chrono/Era;I) range(Ljava/time/temporal/ChronoField;) resolveDate(Ljava/util/Map;Ljava/time/format/ResolverStyle;) toString() zonedDateTime(Ljava/time/Instant;Ljava/time/ZoneId;) zonedDateTime(Ljava/time/temporal/TemporalAccessor;)",
	},
	"java/time/chrono/Era": {
		supers:  "java/time/temporal/TemporalAccessor java/time/temporal/TemporalAdjuster",
		methods: "adjustInto(Ljava/time/temporal/Temporal;) get(Ljava/time/temporal/TemporalField;) getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;) getLong(Ljava/time/temporal/TemporalField;) getValue() isSupported(Ljava/time/temporal/TemporalField;) query(Ljava/time/temporal/TemporalQuery;) range(Ljava/time/temporal/TemporalField;)",
	},
	"java/time/format/DateTimeParseException": {
		supers:  "java/time/DateTimeException",
		methods: "getErrorIndex() getParsedString()",
	},
	"java/time/temporal/Temporal": {
		supers:  "java/time/temporal/TemporalAccessor",
		methods: "isSupported(Ljava/time/temporal/TemporalUnit;) minus(JLjava/time/temporal/TemporalUnit;) minus(Ljava/time/temporal/TemporalAmount;) plus(JLjava/time/temporal/TemporalUnit;) plus(Ljava/time/temporal/TemporalAmount;) until(Ljava/time/temporal/Temporal;Ljava/time/temporal/TemporalUnit;) with(Ljava/time/temporal/TemporalAdjuster;) with(Ljava/time/temporal/TemporalField;J)",
	},
	"java/time/temporal/TemporalAccessor": {
		methods: "get(Ljava/time/temporal/TemporalField;) getLong(Ljava/time/temporal/TemporalField;) isSupported(Ljava/time/temporal/TemporalField;) query(Ljava/time/temporal/TemporalQuery;) range(Ljava/time/temporal/TemporalField;)",
	},
	"java/time/temporal/TemporalAdjuster": {
		methods: "adjustInto(Ljava/time/temporal/Temporal;)",
	},
	"java/time/temporal/TemporalAmount": {
		methods: "addTo(Ljava/time/temporal/Temporal;) get(Ljava/time/temporal/TemporalUnit;) getUnits() subtractFrom(Ljava/time/temporal/Temporal;)",
	},
	"java/time/temporal/TemporalField": {
		methods: "adjustInto(Ljava/time/temporal/Temporal;J) getBaseUnit() getDisplayName(Ljava/util/Locale;) getFrom(Ljava/time/temporal/TemporalAccessor;) getRangeUnit() isDateBased() isSupportedBy(Ljava/time/temporal/TemporalAccessor;) isTimeBased() range() rangeRefinedBy(Ljava/time/temporal/TemporalAccessor;) resolve(Ljava/util/Map;Ljava/time/temporal/TemporalAccessor;Ljava/time/format/ResolverStyle;) toString()",
	},
	"java/time/temporal/TemporalQuery": {
		methods: "queryFrom(Ljava/time/temporal/TemporalAccessor;)",
	},
	"java/time/temporal/TemporalUnit": {
		methods: "addTo(Ljava/time/temporal/Temporal;J) between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;) getDuration() isDateBased() isDurationEstimated() isSupportedBy(Ljava/time/temporal/Temporal;) isTimeBased() toString()",
	},
	"java/time/temporal/UnsupportedTemporalTypeException": {
		supers: "java/time/DateTimeException",
	},
	"java/time/zone/ZoneRulesException": {
		supers: "java/time/DateTimeException",
	},
	"java/time/zone/ZoneRulesProvider": {
		methods: "provideRefresh() provideRules(Ljava/lang/String;Z) provideVersions(Ljava/lang/String;) provideZoneIds()",
	},
	"java/util/AbstractCollection": {
		supers:  "java/util/Collection",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) clear() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) isEmpty() iterator() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) retainAll(Ljava/util/Collection;) size() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/AbstractList": {
		supers:  "java/util/AbstractCollection java/util/List",
		methods: "add(ILjava/lang/Object;) add(Ljava/lang/Object;) addAll(ILjava/util/Collection;) clear() equals(Ljava/lang/Object;) get(I) hashCode() indexOf(Ljava/lang/Object;) iterator() lastIndexOf(Ljava/lang/Object;) listIterator() listIterator(I) remove(I) removeRange(II) set(ILjava/lang/Object;) subList(II)",
	},
	"java/util/AbstractMap": {
		supers:  "java/util/Map",
		methods: "clear() clone() containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() equals(Ljava/lang/Object;) get(Ljava/lang/Object;) hashCode() isEmpty() keySet() put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) remove(Ljava/lang/Object;) size() toString() values()",
	},
	"java/util/AbstractMap$SimpleEntry": {
		supers:  "java/util/Map$Entry java/io/Serializable",
		methods: "equals(Ljava/lang/Object;) getKey() getValue() hashCode() setValue(Ljava/lang/Object;) toString()",
	},
	"java/util/AbstractMap$SimpleImmutableEntry": {
		supers:  "java/util/Map$Entry java/io/Serializable",
		methods: "equals(Ljava/lang/Object;) getKey() getValue() hashCode() setValue(Ljava/lang/Object;) toString()",
	},
	"java/util/AbstractQueue": {
		supers:  "java/util/AbstractCollection java/util/Queue",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) clear() element() remove()",
	},
	"java/util/AbstractSequentialList": {
		supers:  "java/util/AbstractList",
		methods: "add(ILjava/lang/Object;) addAll(ILjava/util/Collection;) get(I) iterator() listIterator(I) remove(I) set(ILjava/lang/Object;)",
	},
	"java/util/AbstractSet": {
		supers:  "java/util/AbstractCollection java/util/Set",
		methods: "equals(Ljava/lang/Object;) hashCode() removeAll(Ljava/util/Collection;)",
	},
	"java/util/ArrayDeque": {
		supers:  "java/util/AbstractCollection java/util/Deque java/lang/Cloneable java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() clone() contains(Ljava/lang/Object;) descendingIterator() element() forEach(Ljava/util/function/Consumer;) getFirst() getLast() isEmpty() iterator() offer(Ljava/lang/Object;) offerFirst(Ljava/lang/Object;) offerLast(Ljava/lang/Object;) peek() peekFirst() peekLast() poll() pollFirst() pollLast() pop() push(Ljava/lang/Object;) remove() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeFirst() removeFirstOccurrence(Ljava/lang/Object;) removeIf(Ljava/util/function/Predicate;) removeLast() removeLastOccurrence(Ljava/lang/Object;) retainAll(Ljava/util/Collection;) size() spliterator() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/ArrayList": {
		supers:  "java/util/AbstractList java/util/List java/util/RandomAccess java/lang/Cloneable java/io/Serializable",
		methods: "add(ILjava/lang/Object;) add(Ljava/lang/Object;) addAll(ILjava/util/Collection;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() clone() contains(Ljava/lang/Object;) ensureCapacity(I) equals(Ljava/lang/Object;) forEach(Ljava/util/function/Consumer;) get(I) getFirst() getLast() hashCode() indexOf(Ljava/lang/Object;) isEmpty() iterator() lastIndexOf(Ljava/lang/Object;) listIterator() listIterator(I) remove(I) remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeFirst() removeIf(Ljava/util/function/Predicate;) removeLast() removeRange(II) replaceAll(Ljava/util/function/UnaryOperator;) retainAll(Ljava/util/Collection;) set(ILjava/lang/Object;) size() sort(Ljava/util/Comparator;) spliterator() subList(II) toArray() toArray([Ljava/lang/Object;) trimToSize()",
	},
	"java/util/Base64": {},
	"java/util/Base64$Decoder": {
		methods: "decode(Ljava/lang/String;) decode(Ljava/nio/ByteBuffer;) decode([B) decode([B[B) wrap(Ljava/io/InputStream;)",
	},
	"java/util/Base64$Encoder": {
		methods: "encode(Ljava/nio/ByteBuffer;) encode([B) encode([B[B) encodeToString([B) withoutPadding() wrap(Ljava/io/OutputStream;)",
	},
	"java/util/BitSet": {
		supers:  "java/lang/Cloneable java/io/Serializable",
		methods: "and(Ljava/util/BitSet;) andNot(Ljava/util/BitSet;) cardinality() clear() clear(I) clear(II) clone() equals(Ljava/lang/Object;) flip(I) flip(II) get(I) get(II) hashCode() intersects(Ljava/util/BitSet;) isEmpty() length() nextClearBit(I) nextSetBit(I) or(Ljava/util/BitSet;) previousClearBit(I) previousSetBit(I) set(I) set(II) set(IIZ) set(IZ) size() stream() toByteArray() toLongArray() toString() xor(Ljava/util/BitSet;)",
	},
	"java/util/Calendar": {
		supers:  "java/io/Serializable java/lang/Cloneable java/lang/Comparable",
		methods: "add(II) after(Ljava/lang/Object;) before(Ljava/lang/Object;) clone() compareTo(Ljava/lang/Object;) compareTo(Ljava/util/Calendar;) complete() computeFields() computeTime() equals(Ljava/lang/Object;) get(I) getActualMaximum(I) getActualMinimum(I) getCalendarType() getDisplayName(IILjava/util/Locale;) getDisplayNames(IILjava/util/Locale;) getFirstDayOfWeek() getGreatestMinimum(I) getLeastMaximum(I) getMaximum(I) getMinimalDaysInFirstWeek() getMinimum(I) getTimeInMillis() getTimeZone() getWeekYear() getWeeksInWeekYear() hashCode() isLenient() isWeekDateSupported() roll(II) roll(IZ) set(II) setFirstDayOfWeek(I) setLenient(Z) setMinimalDaysInFirstWeek(I) setTimeInMillis(J) setTimeZone(Ljava/util/TimeZone;) setWeekDate(III) toString()",
	},
	"java/util/Calendar$Builder": {
		methods: "build() set(II) setCalendarType(Ljava/lang/String;) setDate(III) setFields([I) setInstant(J) setInstant(Ljava/util/Date;) setLenient(Z) setLocale(Ljava/util/Locale;) setTimeOfDay(III) setTimeOfDay(IIII) setTimeZone(Ljava/util/TimeZone;) setWeekDate(III) setWeekDefinition(II)",
	},
	"java/util/Collection": {
		supers:  "java/lang/Iterable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) clear() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) equals(Ljava/lang/Object;) hashCode() isEmpty() iterator() parallelStream() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() stream() toArray() toArray(Ljava/util/function/IntFunction;) toArray([Ljava/lang/Object;)",
	},
	"java/util/Collections": {},
	"java/util/Comparator": {
		methods: "compare(Ljava/lang/Object;Ljava/lang/Object;) equals(Ljava/lang/Object;) reversed() thenComparing(Ljava/util/Comparator;) thenComparing(Ljava/util/function/Function;) thenComparing(Ljava/util/function/Function;Ljava/util/Comparator;) thenComparingDouble(Ljava/util/function/ToDoubleFunction;) thenComparingInt(Ljava/util/function/ToIntFunction;) thenComparingLong(Ljava/util/function/ToLongFunction;)",
	},
	"java/util/ConcurrentModificationException": {
		supers: "java/lang/RuntimeException",
	},
	"java/util/Date": {
		supers:  "java/io/Serializable java/lang/Cloneable java/lang/Comparable",
		methods: "after(Ljava/util/Date;) before(Ljava/util/Date;) clone() compareTo(Ljava/lang/Object;) compareTo(Ljava/util/Date;) equals(Ljava/lang/Object;) getDate() getDay() getHours() getMinutes() getMonth() getSeconds() getTime() getTimezoneOffset() getYear() hashCode() setDate(I) setHours(I) setMinutes(I) setMonth(I) setSeconds(I) setTime(J) setYear(I) toGMTString() toInstant() toLocaleString() toString()",
	},
	"java/util/Deque": {
		supers:  "java/util/Queue java/util/SequencedCollection",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) contains(Ljava/lang/Object;) descendingIterator() element() getFirst() getLast() iterator() offer(Ljava/lang/Object;) offerFirst(Ljava/lang/Object;) offerLast(Ljava/lang/Object;) peek() peekFirst() peekLast() poll() pollFirst() pollLast() pop() push(Ljava/lang/Object;) remove() remove(Ljava/lang/Object;) removeFirst() removeFirstOccurrence(Ljava/lang/Object;) removeLast() removeLastOccurrence(Ljava/lang/Object;) reversed() size()",
	},
	"java/util/Dictionary": {
		methods: "elements() get(Ljava/lang/Object;) isEmpty() keys() put(Ljava/lang/Object;Ljava/lang/Object;) remove(Ljava/lang/Object;) size()",
	},
	"java/util/DoubleSummaryStatistics": {
		supers:  "java/util/function/DoubleConsumer",
		methods: "accept(D) combine(Ljava/util/DoubleSummaryStatistics;) toString()",
	},
	"java/util/DuplicateFormatFlagsException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getFlags() getMessage()",
	},
	"java/util/EmptyStackException": {
		supers: "java/lang/RuntimeException",
	},
	"java/util/EnumMap": {
		supers:  "java/util/AbstractMap java/io/Serializable java/lang/Cloneable",
		methods: "clear() clone() containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() equals(Ljava/lang/Object;) get(Ljava/lang/Object;) hashCode() keySet() put(Ljava/lang/Enum;Ljava/lang/Object;) put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) remove(Ljava/lang/Object;) size() values()",
	},
	"java/util/Enumeration": {
		methods: "asIterator() hasMoreElements() nextElement()",
	},
	"java/util/EventListener": {},
	"java/util/EventListenerProxy": {
		supers:  "java/util/EventListener",
		methods: "getListener()",
	},
	"java/util/EventObject": {
		supers:  "java/io/Serializable",
		methods: "getSource() toString()",
	},
	"java/util/FormatFlagsConversionMismatchException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getConversion() getFlags() getMessage()",
	},
	"java/util/Formattable": {
		methods: "formatTo(Ljava/util/Formatter;III)",
	},
	"java/util/FormattableFlags": {},
	"java/util/FormatterClosedException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/util/GregorianCalendar": {
		supers:  "java/util/Calendar",
		methods: "add(II) clone() computeFields() computeTime() equals(Ljava/lang/Object;) getActualMaximum(I) getActualMinimum(I) getCalendarType() getGreatestMinimum(I) getLeastMaximum(I) getMaximum(I) getMinimum(I) getTimeZone() getWeekYear() getWeeksInWeekYear() hashCode() isLeapYear(I) roll(II) roll(IZ) setGregorianChange(Ljava/util/Date;) setTimeZone(Ljava/util/TimeZone;) setWeekDate(III) toZonedDateTime()",
	},
	"java/util/HashMap": {
		supers:  "java/util/AbstractMap java/util/Map java/lang/Cloneable java/io/Serializable",
		methods: "clear() clone() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) isEmpty() keySet() merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() values()",
	},
	"java/util/HashSet": {
		supers:  "java/util/AbstractSet java/util/Set java/lang/Cloneable java/io/Serializable",
		methods: "add(Ljava/lang/Object;) clear() clone() contains(Ljava/lang/Object;) isEmpty() iterator() remove(Ljava/lang/Object;) size() spliterator() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/Hashtable": {
		supers:  "java/util/Dictionary java/util/Map java/lang/Cloneable java/io/Serializable",
		methods: "clear() clone() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) contains(Ljava/lang/Object;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) elements() entrySet() equals(Ljava/lang/Object;) forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) hashCode() isEmpty() keySet() keys() merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) rehash() remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() toString() values()",
	},
	"java/util/IdentityHashMap": {
		supers:  "java/util/AbstractMap java/util/Map java/io/Serializable java/lang/Cloneable",
		methods: "clear() clone() containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() equals(Ljava/lang/Object;) forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) hashCode() isEmpty() keySet() put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() values()",
	},
	"java/util/IllegalFormatCodePointException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getCodePoint() getMessage()",
	},
	"java/util/IllegalFormatConversionException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getArgumentClass() getConversion() getMessage()",
	},
	"java/util/IllegalFormatException": {
		supers: "java/lang/IllegalArgumentException",
	},
	"java/util/IllegalFormatFlagsException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getFlags() getMessage()",
	},
	"java/util/IllegalFormatPrecisionException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getMessage() getPrecision()",
	},
	"java/util/IllegalFormatWidthException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getMessage() getWidth()",
	},
	"java/util/IllformedLocaleException": {
		supers:  "java/lang/RuntimeException",
		methods: "getErrorIndex()",
	},
	"java/util/InputMismatchException": {
		supers: "java/util/NoSuchElementException",
	},
	"java/util/IntSummaryStatistics": {
		supers:  "java/util/function/IntConsumer",
		methods: "accept(I) combine(Ljava/util/IntSummaryStatistics;) toString()",
	},
	"java/util/InvalidPropertiesFormatException": {
		supers: "java/io/IOException",
	},
	"java/util/Iterator": {
		methods: "forEachRemaining(Ljava/util/function/Consumer;) hasNext() next() remove()",
	},
	"java/util/LinkedHashMap": {
		supers:  "java/util/HashMap java/util/SequencedMap",
		methods: "clear() containsValue(Ljava/lang/Object;) entrySet() forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) keySet() putFirst(Ljava/lang/Object;Ljava/lang/Object;) putLast(Ljava/lang/Object;Ljava/lang/Object;) removeEldestEntry(Ljava/util/Map$Entry;) replaceAll(Ljava/util/function/BiFunction;) reversed() sequencedEntrySet() sequencedKeySet() sequencedValues() values()",
	},
	"java/util/LinkedHashSet": {
		supers:  "java/util/HashSet java/util/SequencedSet java/lang/Cloneable java/io/Serializable",
		methods: "addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) getFirst() getLast() removeFirst() removeLast() reversed() spliterator()",
	},
	"java/util/LinkedList": {
		supers:  "java/util/AbstractSequentialList java/util/List java/util/Deque java/lang/Cloneable java/io/Serializable",
		methods: "add(ILjava/lang/Object;) add(Ljava/lang/Object;) addAll(ILjava/util/Collection;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() clone() contains(Ljava/lang/Object;) descendingIterator() element() get(I) getFirst() getLast() indexOf(Ljava/lang/Object;) lastIndexOf(Ljava/lang/Object;) listIterator(I) offer(Ljava/lang/Object;) offerFirst(Ljava/lang/Object;) offerLast(Ljava/lang/Object;) peek() peekFirst() peekLast() poll() pollFirst() pollLast() pop() push(Ljava/lang/Object;) remove() remove(I) remove(Ljava/lang/Object;) removeFirst() removeFirstOccurrence(Ljava/lang/Object;) removeLast() removeLastOccurrence(Ljava/lang/Object;) reversed() set(ILjava/lang/Object;) size() spliterator() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/List": {
		supers:  "java/util/SequencedCollection",
		methods: "add(ILjava/lang/Object;) add(Ljava/lang/Object;) addAll(ILjava/util/Collection;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) equals(Ljava/lang/Object;) get(I) getFirst() getLast() hashCode() indexOf(Ljava/lang/Object;) isEmpty() iterator() lastIndexOf(Ljava/lang/Object;) listIterator() listIterator(I) remove(I) remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeFirst() removeLast() replaceAll(Ljava/util/function/UnaryOperator;) retainAll(Ljava/util/Collection;) reversed() set(ILjava/lang/Object;) size() sort(Ljava/util/Comparator;) spliterator() subList(II) toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/ListIterator": {
		supers:  "java/util/Iterator",
		methods: "add(Ljava/lang/Object;) hasNext() hasPrevious() next() nextIndex() previous() previousIndex() remove() set(Ljava/lang/Object;)",
	},
	"java/util/ListResourceBundle": {
		supers:  "java/util/ResourceBundle",
		methods: "getContents() getKeys() handleKeySet()",
	},
	"java/util/LongSummaryStatistics": {
		supers:  "java/util/function/LongConsumer java/util/function/IntConsumer",
		methods: "accept(I) accept(J) combine(Ljava/util/LongSummaryStatistics;) toString()",
	},
	"java/util/Map": {
		methods: "clear() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() equals(Ljava/lang/Object;) forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) hashCode() isEmpty() keySet() merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() values()",
	},
	"java/util/Map$Entry": {
		methods: "equals(Ljava/lang/Object;) getKey() getValue() hashCode() setValue(Ljava/lang/Object;)",
	},
	"java/util/MissingFormatArgumentException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getFormatSpecifier() getMessage()",
	},
	"java/util/MissingFormatWidthException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getFormatSpecifier() getMessage()",
	},
	"java/util/MissingResourceException": {
		supers:  "java/lang/RuntimeException",
		methods: "getClassName() getKey()",
	},
	"java/util/NavigableMap": {
		supers:  "java/util/SortedMap",
		methods: "ceilingEntry(Ljava/lang/Object;) ceilingKey(Ljava/lang/Object;) descendingKeySet() descendingMap() firstEntry() floorEntry(Ljava/lang/Object;) floorKey(Ljava/lang/Object;) headMap(Ljava/lang/Object;) headMap(Ljava/lang/Object;Z) higherEntry(Ljava/lang/Object;) higherKey(Ljava/lang/Object;) lastEntry() lowerEntry(Ljava/lang/Object;) lowerKey(Ljava/lang/Object;) navigableKeySet() pollFirstEntry() pollLastEntry() reversed() subMap(Ljava/lang/Object;Ljava/lang/Object;) subMap(Ljava/lang/Object;ZLjava/lang/Object;Z) tailMap(Ljava/lang/Object;) tailMap(Ljava/lang/Object;Z)",
	},
	"java/util/NavigableSet": {
		supers:  "java/util/SortedSet",
		methods: "ceiling(Ljava/lang/Object;) descendingIterator() descendingSet() floor(Ljava/lang/Object;) headSet(Ljava/lang/Object;) headSet(Ljava/lang/Object;Z) higher(Ljava/lang/Object;) iterator() lower(Ljava/lang/Object;) pollFirst() pollLast() removeFirst() removeLast() reversed() subSet(Ljava/lang/Object;Ljava/lang/Object;) subSet(Ljava/lang/Object;ZLjava/lang/Object;Z) tailSet(Ljava/lang/Object;) tailSet(Ljava/lang/Object;Z)",
	},
	"java/util/NoSuchElementException": {
		supers: "java/lang/RuntimeException",
	},
	"java/util/Observable": {
		methods: "addObserver(Ljava/util/Observer;) clearChanged() countObservers() deleteObserver(Ljava/util/Observer;) deleteObservers() hasChanged() notifyObservers() notifyObservers(Ljava/lang/Object;) setChanged()",
	},
	"java/util/Observer": {
		methods: "update(Ljava/util/Observable;Ljava/lang/Object;)",
	},
	"java/util/PrimitiveIterator": {
		supers:  "java/util/Iterator",
		methods: "forEachRemaining(Ljava/lang/Object;)",
	},
	"java/util/PrimitiveIterator$OfDouble": {
		supers:  "java/util/PrimitiveIterator",
		methods: "forEachRemaining(Ljava/lang/Object;) forEachRemaining(Ljava/util/function/Consumer;) forEachRemaining(Ljava/util/function/DoubleConsumer;) next() nextDouble()",
	},
	"java/util/PrimitiveIterator$OfInt": {
		supers:  "java/util/PrimitiveIterator",
		methods: "forEachRemaining(Ljava/lang/Object;) forEachRemaining(Ljava/util/function/Consumer;) forEachRemaining(Ljava/util/function/IntConsumer;) next() nextInt()",
	},
	"java/util/PrimitiveIterator$OfLong": {
		supers:  "java/util/PrimitiveIterator",
		methods: "forEachRemaining(Ljava/lang/Object;) forEachRemaining(Ljava/util/function/Consumer;) forEachRemaining(Ljava/util/function/LongConsumer;) next() nextLong()",
	},
	"java/util/PriorityQueue": {
		supers:  "java/util/AbstractQueue java/io/Serializable",
		methods: "add(Ljava/lang/Object;) clear() comparator() contains(Ljava/lang/Object;) forEach(Ljava/util/function/Consumer;) iterator() offer(Ljava/lang/Object;) peek() poll() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/Properties": {
		supers:  "java/util/Hashtable",
		methods: "clear() clone() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) contains(Ljava/lang/Object;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) elements() entrySet() equals(Ljava/lang/Object;) forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) getProperty(Ljava/lang/String;) getProperty(Ljava/lang/String;Ljava/lang/String;) hashCode() isEmpty() keySet() keys() list(Ljava/io/PrintStream;) list(Ljava/io/PrintWriter;) load(Ljava/io/InputStream;) load(Ljava/io/Reader;) loadFromXML(Ljava/io/InputStream;) merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) propertyNames() put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) rehash() remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) save(Ljava/io/OutputStream;Ljava/lang/String;) setProperty(Ljava/lang/String;Ljava/lang/String;) size() store(Ljava/io/OutputStream;Ljava/lang/String;) store(Ljava/io/Writer;Ljava/lang/String;) storeToXML(Ljava/io/OutputStream;Ljava/lang/String;) storeToXML(Ljava/io/OutputStream;Ljava/lang/String;Ljava/lang/String;) storeToXML(Ljava/io/OutputStream;Ljava/lang/String;Ljava/nio/charset/Charset;) stringPropertyNames() toString() values()",
	},
	"java/util/PropertyResourceBundle": {
		supers:  "java/util/ResourceBundle",
		methods: "getKeys() handleGetObject(Ljava/lang/String;) handleKeySet()",
	},
	"java/util/Queue": {
		supers:  "java/util/Collection",
		methods: "add(Ljava/lang/Object;) element() offer(Ljava/lang/Object;) peek() poll() remove()",
	},
	"java/util/Random": {
		supers:  "java/util/random/RandomGenerator java/io/Serializable",
		methods: "doubles() doubles(DD) doubles(J) doubles(JDD) ints() ints(II) ints(J) ints(JII) longs() longs(J) longs(JJ) longs(JJJ) next(I) nextBoolean() nextBytes([B) nextDouble() nextFloat() nextGaussian() nextInt() nextInt(I) nextLong() setSeed(J)",
	},
	"java/util/RandomAccess": {},
	"java/util/ResourceBundle": {
		methods: "containsKey(Ljava/lang/String;) getBaseBundleName() getKeys() getLocale() handleGetObject(Ljava/lang/String;) handleKeySet() keySet() setParent(Ljava/util/ResourceBundle;)",
	},
	"java/util/ResourceBundle$Control": {
		methods: "getCandidateLocales(Ljava/lang/String;Ljava/util/Locale;) getFallbackLocale(Ljava/lang/String;Ljava/util/Locale;) getFormats(Ljava/lang/String;) getTimeToLive(Ljava/lang/String;Ljava/util/Locale;) needsReload(Ljava/lang/String;Ljava/util/Locale;Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/util/ResourceBundle;J) newBundle(Ljava/lang/String;Ljava/util/Locale;Ljava/lang/String;Ljava/lang/ClassLoader;Z) toBundleName(Ljava/lang/String;Ljava/util/Locale;)",
	},
	"java/util/SequencedCollection": {
		supers:  "java/util/Collection",
		methods: "addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) getFirst() getLast() removeFirst() removeLast() reversed()",
	},
	"java/util/SequencedMap": {
		supers:  "java/util/Map",
		methods: "firstEntry() lastEntry() pollFirstEntry() pollLastEntry() putFirst(Ljava/lang/Object;Ljava/lang/Object;) putLast(Ljava/lang/Object;Ljava/lang/Object;) reversed() sequencedEntrySet() sequencedKeySet() sequencedValues()",
	},
	"java/util/SequencedSet": {
		supers:  "java/util/SequencedCollection java/util/Set",
		methods: "reversed()",
	},
	"java/util/ServiceConfigurationError": {
		supers: "java/lang/Error",
	},
	"java/util/ServiceLoader$Provider": {
		supers:  "java/util/function/Supplier",
		methods: "get() type()",
	},
	"java/util/Set": {
		supers:  "java/util/Collection",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) clear() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) equals(Ljava/lang/Object;) hashCode() isEmpty() iterator() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) retainAll(Ljava/util/Collection;) size() spliterator() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/SimpleTimeZone": {
		supers:  "java/util/TimeZone",
		methods: "clone() equals(Ljava/lang/Object;) getDSTSavings() getOffset(IIIIII) getOffset(J) getRawOffset() hasSameRules(Ljava/util/TimeZone;) hashCode() inDaylightTime(Ljava/util/Date;) observesDaylightTime() setDSTSavings(I) setEndRule(III) setEndRule(IIII) setEndRule(IIIIZ) setRawOffset(I) setStartRule(III) setStartRule(IIII) setStartRule(IIIIZ) setStartYear(I) toString() useDaylightTime()",
	},
	"java/util/SortedMap": {
		supers:  "java/util/SequencedMap",
		methods: "comparator() entrySet() firstKey() headMap(Ljava/lang/Object;) keySet() lastKey() putFirst(Ljava/lang/Object;Ljava/lang/Object;) putLast(Ljava/lang/Object;Ljava/lang/Object;) reversed() subMap(Ljava/lang/Object;Ljava/lang/Object;) tailMap(Ljava/lang/Object;) values()",
	},
	"java/util/SortedSet": {
		supers:  "java/util/Set java/util/SequencedSet",
		methods: "addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) comparator() first() getFirst() getLast() headSet(Ljava/lang/Object;) last() removeFirst() removeLast() reversed() spliterator() subSet(Ljava/lang/Object;Ljava/lang/Object;) tailSet(Ljava/lang/Object;)",
	},
	"java/util/Spliterator": {
		methods: "characteristics() estimateSize() forEachRemaining(Ljava/util/function/Consumer;) getComparator() getExactSizeIfKnown() hasCharacteristics(I) tryAdvance(Ljava/util/function/Consumer;) trySplit()",
	},
	"java/util/Spliterator$OfDouble": {
		supers:  "java/util/Spliterator$OfPrimitive",
		methods: "forEachRemaining(Ljava/lang/Object;) forEachRemaining(Ljava/util/function/Consumer;) forEachRemaining(Ljava/util/function/DoubleConsumer;) tryAdvance(Ljava/lang/Object;) tryAdvance(Ljava/util/function/Consumer;) tryAdvance(Ljava/util/function/DoubleConsumer;) trySplit()",
	},
	"java/util/Spliterator$OfInt": {
		supers:  "java/util/Spliterator$OfPrimitive",
		methods: "forEachRemaining(Ljava/lang/Object;) forEachRemaining(Ljava/util/function/Consumer;) forEachRemaining(Ljava/util/function/IntConsumer;) tryAdvance(Ljava/lang/Object;) tryAdvance(Ljava/util/function/Consumer;) tryAdvance(Ljava/util/function/IntConsumer;) trySplit()",
	},
	"java/util/Spliterator$OfLong": {
		supers:  "java/util/Spliterator$OfPrimitive",
		methods: "forEachRemaining(Ljava/lang/Object;) forEachRemaining(Ljava/util/function/Consumer;) forEachRemaining(Ljava/util/function/LongConsumer;) tryAdvance(Ljava/lang/Object;) tryAdvance(Ljava/util/function/Consumer;) tryAdvance(Ljava/util/function/LongConsumer;) trySplit()",
	},
	"java/util/Spliterator$OfPrimitive": {
		supers:  "java/util/Spliterator",
		methods: "forEachRemaining(Ljava/lang/Object;) tryAdvance(Ljava/lang/Object;) trySplit()",
	},
	"java/util/Spliterators$AbstractDoubleSpliterator": {
		supers:  "java/util/Spliterator$OfDouble",
		methods: "characteristics() estimateSize() trySplit()",
	},
	"java/util/Spliterators$AbstractIntSpliterator": {
		supers:  "java/util/Spliterator$OfInt",
		methods: "characteristics() estimateSize() trySplit()",
	},
	"java/util/Spliterators$AbstractLongSpliterator": {
		supers:  "java/util/Spliterator$OfLong",
		methods: "characteristics() estimateSize() trySplit()",
	},
	"java/util/Spliterators$AbstractSpliterator": {
		supers:  "java/util/Spliterator",
		methods: "characteristics() estimateSize() trySplit()",
	},
	"java/util/Stack": {
		supers:  "java/util/Vector",
		methods: "empty() peek() pop() push(Ljava/lang/Object;) search(Ljava/lang/Object;)",
	},
	"java/util/StringTokenizer": {
		supers:  "java/util/Enumeration",
		methods: "countTokens() hasMoreElements() hasMoreTokens() nextElement() nextToken() nextToken(Ljava/lang/String;)",
	},
	"java/util/TimeZone": {
		supers:  "java/io/Serializable java/lang/Cloneable",
		methods: "clone() getDSTSavings() getDisplayName(ZILjava/util/Locale;) getID() getOffset(IIIIII) getOffset(J) getRawOffset() hasSameRules(Ljava/util/TimeZone;) inDaylightTime(Ljava/util/Date;) observesDaylightTime() setID(Ljava/lang/String;) setRawOffset(I) toZoneId() useDaylightTime()",
	},
	"java/util/Timer": {
		methods: "cancel() purge() schedule(Ljava/util/TimerTask;J) schedule(Ljava/util/TimerTask;JJ) schedule(Ljava/util/TimerTask;Ljava/util/Date;) schedule(Ljava/util/TimerTask;Ljava/util/Date;J) scheduleAtFixedRate(Ljava/util/TimerTask;JJ) scheduleAtFixedRate(Ljava/util/TimerTask;Ljava/util/Date;J)",
	},
	"java/util/TimerTask": {
		supers:  "java/lang/Runnable",
		methods: "cancel() run() scheduledExecutionTime()",
	},
	"java/util/TooManyListenersException": {
		supers: "java/lang/Exception",
	},
	"java/util/TreeMap": {
		supers:  "java/util/AbstractMap java/util/NavigableMap java/lang/Cloneable java/io/Serializable",
		methods: "ceilingEntry(Ljava/lang/Object;) ceilingKey(Ljava/lang/Object;) clear() clone() comparator() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) descendingKeySet() descendingMap() entrySet() firstEntry() firstKey() floorEntry(Ljava/lang/Object;) floorKey(Ljava/lang/Object;) forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) headMap(Ljava/lang/Object;) headMap(Ljava/lang/Object;Z) higherEntry(Ljava/lang/Object;) higherKey(Ljava/lang/Object;) keySet() lastEntry() lastKey() lowerEntry(Ljava/lang/Object;) lowerKey(Ljava/lang/Object;) merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) navigableKeySet() pollFirstEntry() pollLastEntry() put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putFirst(Ljava/lang/Object;Ljava/lang/Object;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) putLast(Ljava/lang/Object;Ljava/lang/Object;) remove(Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() subMap(Ljava/lang/Object;Ljava/lang/Object;) subMap(Ljava/lang/Object;ZLjava/lang/Object;Z) tailMap(Ljava/lang/Object;) tailMap(Ljava/lang/Object;Z) values()",
	},
	"java/util/TreeSet": {
		supers:  "java/util/AbstractSet java/util/NavigableSet java/lang/Cloneable java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) ceiling(Ljava/lang/Object;) clear() clone() comparator() contains(Ljava/lang/Object;) descendingIterator() descendingSet() first() floor(Ljava/lang/Object;) headSet(Ljava/lang/Object;) headSet(Ljava/lang/Object;Z) higher(Ljava/lang/Object;) isEmpty() iterator() last() lower(Ljava/lang/Object;) pollFirst() pollLast() remove(Ljava/lang/Object;) size() spliterator() subSet(Ljava/lang/Object;Ljava/lang/Object;) subSet(Ljava/lang/Object;ZLjava/lang/Object;Z) tailSet(Ljava/lang/Object;) tailSet(Ljava/lang/Object;Z)",
	},
	"java/util/UnknownFormatConversionException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getConversion() getMessage()",
	},
	"java/util/UnknownFormatFlagsException": {
		supers:  "java/util/IllegalFormatException",
		methods: "getFlags() getMessage()",
	},
	"java/util/Vector": {
		supers:  "java/util/AbstractList java/util/List java/util/RandomAccess java/lang/Cloneable java/io/Serializable",
		methods: "add(ILjava/lang/Object;) add(Ljava/lang/Object;) addAll(ILjava/util/Collection;) addAll(Ljava/util/Collection;) addElement(Ljava/lang/Object;) capacity() clear() clone() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) copyInto([Ljava/lang/Object;) elementAt(I) elements() ensureCapacity(I) equals(Ljava/lang/Object;) firstElement() forEach(Ljava/util/function/Consumer;) get(I) hashCode() indexOf(Ljava/lang/Object;) indexOf(Ljava/lang/Object;I) insertElementAt(Ljava/lang/Object;I) isEmpty() iterator() lastElement() lastIndexOf(Ljava/lang/Object;) lastIndexOf(Ljava/lang/Object;I) listIterator() listIterator(I) remove(I) remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeAllElements() removeElement(Ljava/lang/Object;) removeElementAt(I) removeIf(Ljava/util/function/Predicate;) removeRange(II) replaceAll(Ljava/util/function/UnaryOperator;) retainAll(Ljava/util/Collection;) set(ILjava/lang/Object;) setElementAt(Ljava/lang/Object;I) setSize(I) size() sort(Ljava/util/Comparator;) spliterator() subList(II) toArray() toArray([Ljava/lang/Object;) toString() trimToSize()",
	},
	"java/util/WeakHashMap": {
		supers:  "java/util/AbstractMap java/util/Map",
		methods: "clear() containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) isEmpty() keySet() put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) remove(Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() values()",
	},
	"java/util/concurrent/AbstractExecutorService": {
		supers:  "java/util/concurrent/ExecutorService",
		methods: "invokeAll(Ljava/util/Collection;) invokeAll(Ljava/util/Collection;JLjava/util/concurrent/TimeUnit;) invokeAny(Ljava/util/Collection;) invokeAny(Ljava/util/Collection;JLjava/util/concurrent/TimeUnit;) newTaskFor(Ljava/lang/Runnable;Ljava/lang/Object;) newTaskFor(Ljava/util/concurrent/Callable;) submit(Ljava/lang/Runnable;) submit(Ljava/lang/Runnable;Ljava/lang/Object;) submit(Ljava/util/concurrent/Callable;)",
	},
	"java/util/concurrent/ArrayBlockingQueue": {
		supers:  "java/util/AbstractQueue java/util/concurrent/BlockingQueue java/io/Serializable",
		methods: "add(Ljava/lang/Object;) clear() contains(Ljava/lang/Object;) drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) forEach(Ljava/util/function/Consumer;) iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) remainingCapacity() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() take() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/BlockingDeque": {
		supers:  "java/util/concurrent/BlockingQueue java/util/Deque",
		methods: "add(Ljava/lang/Object;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) contains(Ljava/lang/Object;) element() iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) offerFirst(Ljava/lang/Object;) offerFirst(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) offerLast(Ljava/lang/Object;) offerLast(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) pollFirst(JLjava/util/concurrent/TimeUnit;) pollLast(JLjava/util/concurrent/TimeUnit;) push(Ljava/lang/Object;) put(Ljava/lang/Object;) putFirst(Ljava/lang/Object;) putLast(Ljava/lang/Object;) remove() remove(Ljava/lang/Object;) removeFirstOccurrence(Ljava/lang/Object;) removeLastOccurrence(Ljava/lang/Object;) size() take() takeFirst() takeLast()",
	},
	"java/util/concurrent/BlockingQueue": {
		supers:  "java/util/Queue",
		methods: "add(Ljava/lang/Object;) contains(Ljava/lang/Object;) drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) remainingCapacity() remove(Ljava/lang/Object;) take()",
	},
	"java/util/concurrent/BrokenBarrierException": {
		supers: "java/lang/Exception",
	},
	"java/util/concurrent/Callable": {
		methods: "call()",
	},
	"java/util/concurrent/CancellationException": {
		supers: "java/lang/IllegalStateException",
	},
	"java/util/concurrent/CompletableFuture": {
		supers:  "java/util/concurrent/Future java/util/concurrent/CompletionStage",
		methods: "acceptEither(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Consumer;) acceptEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Consumer;) acceptEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Consumer;Ljava/util/concurrent/Executor;) applyToEither(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Function;) applyToEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Function;) applyToEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Function;Ljava/util/concurrent/Executor;) cancel(Z) complete(Ljava/lang/Object;) completeAsync(Ljava/util/function/Supplier;) completeAsync(Ljava/util/function/Supplier;Ljava/util/concurrent/Executor;) completeExceptionally(Ljava/lang/Throwable;) completeOnTimeout(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) copy() defaultExecutor() exceptionNow() exceptionally(Ljava/util/function/Function;) exceptionallyAsync(Ljava/util/function/Function;) exceptionallyAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) exceptionallyCompose(Ljava/util/function/Function;) exceptionallyComposeAsync(Ljava/util/function/Function;) exceptionallyComposeAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) get() get(JLjava/util/concurrent/TimeUnit;) getNow(Ljava/lang/Object;) getNumberOfDependents() handle(Ljava/util/function/BiFunction;) handleAsync(Ljava/util/function/BiFunction;) handleAsync(Ljava/util/function/BiFunction;Ljava/util/concurrent/Executor;) isCancelled() isCompletedExceptionally() isDone() join() minimalCompletionStage() newIncompleteFuture() obtrudeException(Ljava/lang/Throwable;) obtrudeValue(Ljava/lang/Object;) orTimeout(JLjava/util/concurrent/TimeUnit;) resultNow() runAfterBoth(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;Ljava/util/concurrent/Executor;) runAfterEither(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;Ljava/util/concurrent/Executor;) state() thenAccept(Ljava/util/function/Consumer;) thenAcceptAsync(Ljava/util/function/Consumer;) thenAcceptAsync(Ljava/util/function/Consumer;Ljava/util/concurrent/Executor;) thenAcceptBoth(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiConsumer;) thenAcceptBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiConsumer;) thenAcceptBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiConsumer;Ljava/util/concurrent/Executor;) thenApply(Ljava/util/function/Function;) thenApplyAsync(Ljava/util/function/Function;) thenApplyAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) thenCombine(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiFunction;) thenCombineAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiFunction;) thenCombineAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiFunction;Ljava/util/concurrent/Executor;) thenCompose(Ljava/util/function/Function;) thenComposeAsync(Ljava/util/function/Function;) thenComposeAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) thenRun(Ljava/lang/Runnable;) thenRunAsync(Ljava/lang/Runnable;) thenRunAsync(Ljava/lang/Runnable;Ljava/util/concurrent/Executor;) toCompletableFuture() toString() whenComplete(Ljava/util/function/BiConsumer;) whenCompleteAsync(Ljava/util/function/BiConsumer;) whenCompleteAsync(Ljava/util/function/BiConsumer;Ljava/util/concurrent/Executor;)",
	},
	"java/util/concurrent/CompletableFuture$AsynchronousCompletionTask": {},
	"java/util/concurrent/CompletionException": {
		supers: "java/lang/RuntimeException",
	},
	"java/util/concurrent/CompletionService": {
		methods: "poll() poll(JLjava/util/concurrent/TimeUnit;) submit(Ljava/lang/Runnable;Ljava/lang/Object;) submit(Ljava/util/concurrent/Callable;) take()",
	},
	"java/util/concurrent/CompletionStage": {
		methods: "acceptEither(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Consumer;) acceptEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Consumer;) acceptEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Consumer;Ljava/util/concurrent/Executor;) applyToEither(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Function;) applyToEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Function;) applyToEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/Function;Ljava/util/concurrent/Executor;) exceptionally(Ljava/util/function/Function;) exceptionallyAsync(Ljava/util/function/Function;) exceptionallyAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) exceptionallyCompose(Ljava/util/function/Function;) exceptionallyComposeAsync(Ljava/util/function/Function;) exceptionallyComposeAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) handle(Ljava/util/function/BiFunction;) handleAsync(Ljava/util/function/BiFunction;) handleAsync(Ljava/util/function/BiFunction;Ljava/util/concurrent/Executor;) runAfterBoth(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;Ljava/util/concurrent/Executor;) runAfterEither(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;) runAfterEitherAsync(Ljava/util/concurrent/CompletionStage;Ljava/lang/Runnable;Ljava/util/concurrent/Executor;) thenAccept(Ljava/util/function/Consumer;) thenAcceptAsync(Ljava/util/function/Consumer;) thenAcceptAsync(Ljava/util/function/Consumer;Ljava/util/concurrent/Executor;) thenAcceptBoth(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiConsumer;) thenAcceptBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiConsumer;) thenAcceptBothAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiConsumer;Ljava/util/concurrent/Executor;) thenApply(Ljava/util/function/Function;) thenApplyAsync(Ljava/util/function/Function;) thenApplyAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) thenCombine(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiFunction;) thenCombineAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiFunction;) thenCombineAsync(Ljava/util/concurrent/CompletionStage;Ljava/util/function/BiFunction;Ljava/util/concurrent/Executor;) thenCompose(Ljava/util/function/Function;) thenComposeAsync(Ljava/util/function/Function;) thenComposeAsync(Ljava/util/function/Function;Ljava/util/concurrent/Executor;) thenRun(Ljava/lang/Runnable;) thenRunAsync(Ljava/lang/Runnable;) thenRunAsync(Ljava/lang/Runnable;Ljava/util/concurrent/Executor;) toCompletableFuture() whenComplete(Ljava/util/function/BiConsumer;) whenCompleteAsync(Ljava/util/function/BiConsumer;) whenCompleteAsync(Ljava/util/function/BiConsumer;Ljava/util/concurrent/Executor;)",
	},
	"java/util/concurrent/ConcurrentHashMap": {
		supers:  "java/util/AbstractMap java/util/concurrent/ConcurrentMap java/io/Serializable",
		methods: "clear() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) contains(Ljava/lang/Object;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) elements() entrySet() equals(Ljava/lang/Object;) forEach(JLjava/util/function/BiConsumer;) forEach(JLjava/util/function/BiFunction;Ljava/util/function/Consumer;) forEach(Ljava/util/function/BiConsumer;) forEachEntry(JLjava/util/function/Consumer;) forEachEntry(JLjava/util/function/Function;Ljava/util/function/Consumer;) forEachKey(JLjava/util/function/Consumer;) forEachKey(JLjava/util/function/Function;Ljava/util/function/Consumer;) forEachValue(JLjava/util/function/Consumer;) forEachValue(JLjava/util/function/Function;Ljava/util/function/Consumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) hashCode() isEmpty() keySet() keySet(Ljava/lang/Object;) keys() mappingCount() merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) reduce(JLjava/util/function/BiFunction;Ljava/util/function/BiFunction;) reduceEntries(JLjava/util/function/BiFunction;) reduceEntries(JLjava/util/function/Function;Ljava/util/function/BiFunction;) reduceEntriesToDouble(JLjava/util/function/ToDoubleFunction;DLjava/util/function/DoubleBinaryOperator;) reduceEntriesToInt(JLjava/util/function/ToIntFunction;ILjava/util/function/IntBinaryOperator;) reduceEntriesToLong(JLjava/util/function/ToLongFunction;JLjava/util/function/LongBinaryOperator;) reduceKeys(JLjava/util/function/BiFunction;) reduceKeys(JLjava/util/function/Function;Ljava/util/function/BiFunction;) reduceKeysToDouble(JLjava/util/function/ToDoubleFunction;DLjava/util/function/DoubleBinaryOperator;) reduceKeysToInt(JLjava/util/function/ToIntFunction;ILjava/util/function/IntBinaryOperator;) reduceKeysToLong(JLjava/util/function/ToLongFunction;JLjava/util/function/LongBinaryOperator;) reduceToDouble(JLjava/util/function/ToDoubleBiFunction;DLjava/util/function/DoubleBinaryOperator;) reduceToInt(JLjava/util/function/ToIntBiFunction;ILjava/util/function/IntBinaryOperator;) reduceToLong(JLjava/util/function/ToLongBiFunction;JLjava/util/function/LongBinaryOperator;) reduceValues(JLjava/util/function/BiFunction;) reduceValues(JLjava/util/function/Function;Ljava/util/function/BiFunction;) reduceValuesToDouble(JLjava/util/function/ToDoubleFunction;DLjava/util/function/DoubleBinaryOperator;) reduceValuesToInt(JLjava/util/function/ToIntFunction;ILjava/util/function/IntBinaryOperator;) reduceValuesToLong(JLjava/util/function/ToLongFunction;JLjava/util/function/LongBinaryOperator;) remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) search(JLjava/util/function/BiFunction;) searchEntries(JLjava/util/function/Function;) searchKeys(JLjava/util/function/Function;) searchValues(JLjava/util/function/Function;) size() toString() values()",
	},
	"java/util/concurrent/ConcurrentLinkedDeque": {
		supers:  "java/util/AbstractCollection java/util/Deque java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() contains(Ljava/lang/Object;) descendingIterator() element() forEach(Ljava/util/function/Consumer;) getFirst() getLast() isEmpty() iterator() offer(Ljava/lang/Object;) offerFirst(Ljava/lang/Object;) offerLast(Ljava/lang/Object;) peek() peekFirst() peekLast() poll() pollFirst() pollLast() pop() push(Ljava/lang/Object;) remove() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeFirst() removeFirstOccurrence(Ljava/lang/Object;) removeIf(Ljava/util/function/Predicate;) removeLast() removeLastOccurrence(Ljava/lang/Object;) retainAll(Ljava/util/Collection;) size() spliterator() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/ConcurrentLinkedQueue": {
		supers:  "java/util/AbstractQueue java/util/Queue java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) clear() contains(Ljava/lang/Object;) forEach(Ljava/util/function/Consumer;) isEmpty() iterator() offer(Ljava/lang/Object;) peek() poll() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/ConcurrentMap": {
		supers:  "java/util/Map",
		methods: "compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) forEach(Ljava/util/function/BiConsumer;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;)",
	},
	"java/util/concurrent/ConcurrentNavigableMap": {
		supers:  "java/util/concurrent/ConcurrentMap java/util/NavigableMap",
		methods: "descendingKeySet() descendingMap() headMap(Ljava/lang/Object;) headMap(Ljava/lang/Object;Z) keySet() navigableKeySet() subMap(Ljava/lang/Object;Ljava/lang/Object;) subMap(Ljava/lang/Object;ZLjava/lang/Object;Z) tailMap(Ljava/lang/Object;) tailMap(Ljava/lang/Object;Z)",
	},
	"java/util/concurrent/ConcurrentSkipListMap": {
		supers:  "java/util/AbstractMap java/util/concurrent/ConcurrentNavigableMap java/lang/Cloneable java/io/Serializable",
		methods: "ceilingEntry(Ljava/lang/Object;) ceilingKey(Ljava/lang/Object;) clear() clone() comparator() compute(Ljava/lang/Object;Ljava/util/function/BiFunction;) computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;) computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;) containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) descendingKeySet() descendingMap() entrySet() equals(Ljava/lang/Object;) firstEntry() firstKey() floorEntry(Ljava/lang/Object;) floorKey(Ljava/lang/Object;) forEach(Ljava/util/function/BiConsumer;) get(Ljava/lang/Object;) getOrDefault(Ljava/lang/Object;Ljava/lang/Object;) headMap(Ljava/lang/Object;) headMap(Ljava/lang/Object;Z) higherEntry(Ljava/lang/Object;) higherKey(Ljava/lang/Object;) isEmpty() keySet() lastEntry() lastKey() lowerEntry(Ljava/lang/Object;) lowerKey(Ljava/lang/Object;) merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;) navigableKeySet() pollFirstEntry() pollLastEntry() put(Ljava/lang/Object;Ljava/lang/Object;) putFirst(Ljava/lang/Object;Ljava/lang/Object;) putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;) putLast(Ljava/lang/Object;Ljava/lang/Object;) remove(Ljava/lang/Object;) remove(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;) replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) replaceAll(Ljava/util/function/BiFunction;) size() subMap(Ljava/lang/Object;Ljava/lang/Object;) subMap(Ljava/lang/Object;ZLjava/lang/Object;Z) tailMap(Ljava/lang/Object;) tailMap(Ljava/lang/Object;Z) values()",
	},
	"java/util/concurrent/ConcurrentSkipListSet": {
		supers:  "java/util/AbstractSet java/util/NavigableSet java/lang/Cloneable java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) ceiling(Ljava/lang/Object;) clear() clone() comparator() contains(Ljava/lang/Object;) descendingIterator() descendingSet() equals(Ljava/lang/Object;) first() floor(Ljava/lang/Object;) headSet(Ljava/lang/Object;) headSet(Ljava/lang/Object;Z) higher(Ljava/lang/Object;) isEmpty() iterator() last() lower(Ljava/lang/Object;) pollFirst() pollLast() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) size() spliterator() subSet(Ljava/lang/Object;Ljava/lang/Object;) subSet(Ljava/lang/Object;ZLjava/lang/Object;Z) tailSet(Ljava/lang/Object;) tailSet(Ljava/lang/Object;Z)",
	},
	"java/util/concurrent/CopyOnWriteArrayList": {
		supers:  "java/util/List java/util/RandomAccess java/lang/Cloneable java/io/Serializable",
		methods: "add(ILjava/lang/Object;) add(Ljava/lang/Object;) addAll(ILjava/util/Collection;) addAll(Ljava/util/Collection;) addAllAbsent(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addIfAbsent(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() clone() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) equals(Ljava/lang/Object;) forEach(Ljava/util/function/Consumer;) get(I) getFirst() getLast() hashCode() indexOf(Ljava/lang/Object;) indexOf(Ljava/lang/Object;I) isEmpty() iterator() lastIndexOf(Ljava/lang/Object;) lastIndexOf(Ljava/lang/Object;I) listIterator() listIterator(I) remove(I) remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeFirst() removeIf(Ljava/util/function/Predicate;) removeLast() replaceAll(Ljava/util/function/UnaryOperator;) retainAll(Ljava/util/Collection;) reversed() set(ILjava/lang/Object;) size() sort(Ljava/util/Comparator;) spliterator() subList(II) toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/CopyOnWriteArraySet": {
		supers:  "java/util/AbstractSet java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) clear() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) equals(Ljava/lang/Object;) forEach(Ljava/util/function/Consumer;) isEmpty() iterator() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/concurrent/CountDownLatch": {
		methods: "await() await(JLjava/util/concurrent/TimeUnit;) countDown() getCount() toString()",
	},
	"java/util/concurrent/CountedCompleter": {
		supers:  "java/util/concurrent/ForkJoinTask",
		methods: "complete(Ljava/lang/Object;) compute() getRawResult() onCompletion(Ljava/util/concurrent/CountedCompleter;) onExceptionalCompletion(Ljava/lang/Throwable;Ljava/util/concurrent/CountedCompleter;) setRawResult(Ljava/lang/Object;)",
	},
	"java/util/concurrent/CyclicBarrier": {
		methods: "await() await(JLjava/util/concurrent/TimeUnit;) getNumberWaiting() getParties() isBroken() reset()",
	},
	"java/util/concurrent/DelayQueue": {
		supers:  "java/util/AbstractQueue java/util/concurrent/BlockingQueue",
		methods: "add(Ljava/lang/Object;) add(Ljava/util/concurrent/Delayed;) clear() drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) offer(Ljava/util/concurrent/Delayed;) offer(Ljava/util/concurrent/Delayed;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) put(Ljava/util/concurrent/Delayed;) remainingCapacity() remove() remove(Ljava/lang/Object;) size() take() toArray() toArray([Ljava/lang/Object;)",
	},
	"java/util/concurrent/Delayed": {
		supers:  "java/lang/Comparable",
		methods: "getDelay(Ljava/util/concurrent/TimeUnit;)",
	},
	"java/util/concurrent/Exchanger": {
		methods: "exchange(Ljava/lang/Object;) exchange(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;)",
	},
	"java/util/concurrent/ExecutionException": {
		supers: "java/lang/Exception",
	},
	"java/util/concurrent/Executor": {
		methods: "execute(Ljava/lang/Runnable;)",
	},
	"java/util/concurrent/ExecutorCompletionService": {
		supers:  "java/util/concurrent/CompletionService",
		methods: "poll() poll(JLjava/util/concurrent/TimeUnit;) submit(Ljava/lang/Runnable;Ljava/lang/Object;) submit(Ljava/util/concurrent/Callable;) take()",
	},
	"java/util/concurrent/ExecutorService": {
		supers:  "java/util/concurrent/Executor java/lang/AutoCloseable",
		methods: "awaitTermination(JLjava/util/concurrent/TimeUnit;) close() invokeAll(Ljava/util/Collection;) invokeAll(Ljava/util/Collection;JLjava/util/concurrent/TimeUnit;) invokeAny(Ljava/util/Collection;) invokeAny(Ljava/util/Collection;JLjava/util/concurrent/TimeUnit;) isShutdown() isTerminated() shutdown() shutdownNow() submit(Ljava/lang/Runnable;) submit(Ljava/lang/Runnable;Ljava/lang/Object;) submit(Ljava/util/concurrent/Callable;)",
	},
	"java/util/concurrent/Executors": {},
	"java/util/concurrent/Flow$Processor": {
		supers: "java/util/concurrent/Flow$Subscriber java/util/concurrent/Flow$Publisher",
	},
	"java/util/concurrent/Flow$Publisher": {
		methods: "subscribe(Ljava/util/concurrent/Flow$Subscriber;)",
	},
	"java/util/concurrent/Flow$Subscriber": {
		methods: "onComplete() onError(Ljava/lang/Throwable;) onNext(Ljava/lang/Object;) onSubscribe(Ljava/util/concurrent/Flow$Subscription;)",
	},
	"java/util/concurrent/Flow$Subscription": {
		methods: "cancel() request(J)",
	},
	"java/util/concurrent/ForkJoinPool": {
		supers:  "java/util/concurrent/AbstractExecutorService",
		methods: "awaitQuiescence(JLjava/util/concurrent/TimeUnit;) awaitTermination(JLjava/util/concurrent/TimeUnit;) close() drainTasksTo(Ljava/util/Collection;) execute(Ljava/lang/Runnable;) execute(Ljava/util/concurrent/ForkJoinTask;) externalSubmit(Ljava/util/concurrent/ForkJoinTask;) getActiveThreadCount() getAsyncMode() getFactory() getParallelism() getPoolSize() getQueuedSubmissionCount() getQueuedTaskCount() getRunningThreadCount() getStealCount() getUncaughtExceptionHandler() hasQueuedSubmissions() invoke(Ljava/util/concurrent/ForkJoinTask;) invokeAll(Ljava/util/Collection;) invokeAll(Ljava/util/Collection;JLjava/util/concurrent/TimeUnit;) invokeAny(Ljava/util/Collection;) invokeAny(Ljava/util/Collection;JLjava/util/concurrent/TimeUnit;) isQuiescent() isShutdown() isTerminated() isTerminating() lazySubmit(Ljava/util/concurrent/ForkJoinTask;) newTaskFor(Ljava/lang/Runnable;Ljava/lang/Object;) newTaskFor(Ljava/util/concurrent/Callable;) pollSubmission() setParallelism(I) shutdown() shutdownNow() submit(Ljava/lang/Runnable;) submit(Ljava/lang/Runnable;Ljava/lang/Object;) submit(Ljava/util/concurrent/Callable;) submit(Ljava/util/concurrent/ForkJoinTask;) toString()",
	},
	"java/util/concurrent/ForkJoinPool$ForkJoinWorkerThreadFactory": {
		methods: "newThread(Ljava/util/concurrent/ForkJoinPool;)",
	},
	"java/util/concurrent/ForkJoinPool$ManagedBlocker": {
		methods: "block() isReleasable()",
	},
	"java/util/concurrent/ForkJoinTask": {
		supers:  "java/util/concurrent/Future java/io/Serializable",
		methods: "cancel(Z) complete(Ljava/lang/Object;) completeExceptionally(Ljava/lang/Throwable;) exceptionNow() exec() getRawResult() reinitialize() resultNow() setRawResult(Ljava/lang/Object;) state() tryUnfork()",
	},
	"java/util/concurrent/ForkJoinWorkerThread": {
		supers:  "java/lang/Thread",
		methods: "getPool() getPoolIndex() getQueuedTaskCount() onStart() onTermination(Ljava/lang/Throwable;) run()",
	},
	"java/util/concurrent/Future": {
		methods: "cancel(Z) exceptionNow() get() get(JLjava/util/concurrent/TimeUnit;) isCancelled() isDone() resultNow() state()",
	},
	"java/util/concurrent/FutureTask": {
		supers:  "java/util/concurrent/RunnableFuture",
		methods: "cancel(Z) done() exceptionNow() get() get(JLjava/util/concurrent/TimeUnit;) isCancelled() isDone() resultNow() run() runAndReset() set(Ljava/lang/Object;) setException(Ljava/lang/Throwable;) state() toString()",
	},
	"java/util/concurrent/LinkedBlockingDeque": {
		supers:  "java/util/AbstractQueue java/util/concurrent/BlockingDeque java/io/Serializable",
		methods: "add(Ljava/lang/Object;) addAll(Ljava/util/Collection;) addFirst(Ljava/lang/Object;) addLast(Ljava/lang/Object;) clear() contains(Ljava/lang/Object;) descendingIterator() drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) element() forEach(Ljava/util/function/Consumer;) getFirst() getLast() iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) offerFirst(Ljava/lang/Object;) offerFirst(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) offerLast(Ljava/lang/Object;) offerLast(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() peekFirst() peekLast() poll() poll(JLjava/util/concurrent/TimeUnit;) pollFirst() pollFirst(JLjava/util/concurrent/TimeUnit;) pollLast() pollLast(JLjava/util/concurrent/TimeUnit;) pop() push(Ljava/lang/Object;) put(Ljava/lang/Object;) putFirst(Ljava/lang/Object;) putLast(Ljava/lang/Object;) remainingCapacity() remove() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeFirst() removeFirstOccurrence(Ljava/lang/Object;) removeIf(Ljava/util/function/Predicate;) removeLast() removeLastOccurrence(Ljava/lang/Object;) retainAll(Ljava/util/Collection;) size() spliterator() take() takeFirst() takeLast() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/LinkedBlockingQueue": {
		supers:  "java/util/AbstractQueue java/util/concurrent/BlockingQueue java/io/Serializable",
		methods: "clear() contains(Ljava/lang/Object;) drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) forEach(Ljava/util/function/Consumer;) iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) remainingCapacity() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() take() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/LinkedTransferQueue": {
		supers:  "java/util/AbstractQueue java/util/concurrent/TransferQueue java/io/Serializable",
		methods: "add(Ljava/lang/Object;) clear() contains(Ljava/lang/Object;) drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) forEach(Ljava/util/function/Consumer;) getWaitingConsumerCount() hasWaitingConsumer() isEmpty() iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) remainingCapacity() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() take() toArray() toArray([Ljava/lang/Object;) toString() transfer(Ljava/lang/Object;) tryTransfer(Ljava/lang/Object;) tryTransfer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;)",
	},
	"java/util/concurrent/Phaser": {
		methods: "arrive() arriveAndAwaitAdvance() arriveAndDeregister() awaitAdvance(I) awaitAdvanceInterruptibly(I) awaitAdvanceInterruptibly(IJLjava/util/concurrent/TimeUnit;) bulkRegister(I) forceTermination() getArrivedParties() getParent() getRegisteredParties() getRoot() getUnarrivedParties() isTerminated() onAdvance(II) register() toString()",
	},
	"java/util/concurrent/PriorityBlockingQueue": {
		supers:  "java/util/AbstractQueue java/util/concurrent/BlockingQueue java/io/Serializable",
		methods: "add(Ljava/lang/Object;) clear() comparator() contains(Ljava/lang/Object;) drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) forEach(Ljava/util/function/Consumer;) iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) remainingCapacity() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) removeIf(Ljava/util/function/Predicate;) retainAll(Ljava/util/Collection;) size() spliterator() take() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/RecursiveAction": {
		supers:  "java/util/concurrent/ForkJoinTask",
		methods: "compute() getRawResult() setRawResult(Ljava/lang/Object;)",
	},
	"java/util/concurrent/RecursiveTask": {
		supers:  "java/util/concurrent/ForkJoinTask",
		methods: "compute()",
	},
	"java/util/concurrent/RejectedExecutionException": {
		supers: "java/lang/RuntimeException",
	},
	"java/util/concurrent/RejectedExecutionHandler": {
		methods: "rejectedExecution(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)",
	},
	"java/util/concurrent/RunnableFuture": {
		supers:  "java/lang/Runnable java/util/concurrent/Future",
		methods: "run()",
	},
	"java/util/concurrent/RunnableScheduledFuture": {
		supers:  "java/util/concurrent/RunnableFuture java/util/concurrent/ScheduledFuture",
		methods: "isPeriodic()",
	},
	"java/util/concurrent/ScheduledExecutorService": {
		supers:  "java/util/concurrent/ExecutorService",
		methods: "schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;) schedule(Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;) scheduleAtFixedRate(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;) scheduleWithFixedDelay(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;)",
	},
	"java/util/concurrent/ScheduledFuture": {
		supers: "java/util/concurrent/Delayed java/util/concurrent/Future",
	},
	"java/util/concurrent/ScheduledThreadPoolExecutor": {
		supers:  "java/util/concurrent/ThreadPoolExecutor java/util/concurrent/ScheduledExecutorService",
		methods: "decorateTask(Ljava/lang/Runnable;Ljava/util/concurrent/RunnableScheduledFuture;) decorateTask(Ljava/util/concurrent/Callable;Ljava/util/concurrent/RunnableScheduledFuture;) execute(Ljava/lang/Runnable;) getContinueExistingPeriodicTasksAfterShutdownPolicy() getExecuteExistingDelayedTasksAfterShutdownPolicy() getQueue() getRemoveOnCancelPolicy() schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;) schedule(Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;) scheduleAtFixedRate(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;) scheduleWithFixedDelay(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;) setContinueExistingPeriodicTasksAfterShutdownPolicy(Z) setExecuteExistingDelayedTasksAfterShutdownPolicy(Z) setRemoveOnCancelPolicy(Z) shutdown() shutdownNow() submit(Ljava/lang/Runnable;) submit(Ljava/lang/Runnable;Ljava/lang/Object;) submit(Ljava/util/concurrent/Callable;)",
	},
	"java/util/concurrent/Semaphore": {
		supers:  "java/io/Serializable",
		methods: "acquire() acquire(I) acquireUninterruptibly() acquireUninterruptibly(I) availablePermits() drainPermits() getQueuedThreads() isFair() reducePermits(I) release() release(I) toString() tryAcquire() tryAcquire(I) tryAcquire(IJLjava/util/concurrent/TimeUnit;) tryAcquire(JLjava/util/concurrent/TimeUnit;)",
	},
	"java/util/concurrent/StructuredTaskScope": {
		supers:  "java/lang/AutoCloseable",
		methods: "close() fork(Ljava/util/concurrent/Callable;) handleComplete(Ljava/util/concurrent/StructuredTaskScope$Subtask;) join() joinUntil(Ljava/time/Instant;) shutdown() toString()",
	},
	"java/util/concurrent/SubmissionPublisher": {
		supers:  "java/util/concurrent/Flow$Publisher java/lang/AutoCloseable",
		methods: "close() closeExceptionally(Ljava/lang/Throwable;) consume(Ljava/util/function/Consumer;) estimateMaximumLag() estimateMinimumDemand() getClosedException() getExecutor() getMaxBufferCapacity() getNumberOfSubscribers() getSubscribers() hasSubscribers() isClosed() isSubscribed(Ljava/util/concurrent/Flow$Subscriber;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;Ljava/util/function/BiPredicate;) offer(Ljava/lang/Object;Ljava/util/function/BiPredicate;) submit(Ljava/lang/Object;) subscribe(Ljava/util/concurrent/Flow$Subscriber;)",
	},
	"java/util/concurrent/SynchronousQueue": {
		supers:  "java/util/AbstractQueue java/util/concurrent/BlockingQueue java/io/Serializable",
		methods: "clear() contains(Ljava/lang/Object;) containsAll(Ljava/util/Collection;) drainTo(Ljava/util/Collection;) drainTo(Ljava/util/Collection;I) isEmpty() iterator() offer(Ljava/lang/Object;) offer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;) peek() poll() poll(JLjava/util/concurrent/TimeUnit;) put(Ljava/lang/Object;) remainingCapacity() remove(Ljava/lang/Object;) removeAll(Ljava/util/Collection;) retainAll(Ljava/util/Collection;) size() spliterator() take() toArray() toArray([Ljava/lang/Object;) toString()",
	},
	"java/util/concurrent/ThreadFactory": {
		methods: "newThread(Ljava/lang/Runnable;)",
	},
	"java/util/concurrent/ThreadPoolExecutor": {
		supers:  "java/util/concurrent/AbstractExecutorService",
		methods: "afterExecute(Ljava/lang/Runnable;Ljava/lang/Throwable;) allowCoreThreadTimeOut(Z) allowsCoreThreadTimeOut() awaitTermination(JLjava/util/concurrent/TimeUnit;) beforeExecute(Ljava/lang/Thread;Ljava/lang/Runnable;) execute(Ljava/lang/Runnable;) finalize() getActiveCount() getCompletedTaskCount() getCorePoolSize() getKeepAliveTime(Ljava/util/concurrent/TimeUnit;) getLargestPoolSize() getMaximumPoolSize() getPoolSize() getQueue() getRejectedExecutionHandler() getTaskCount() getThreadFactory() isShutdown() isTerminated() isTerminating() prestartAllCoreThreads() prestartCoreThread() purge() remove(Ljava/lang/Runnable;) setCorePoolSize(I) setKeepAliveTime(JLjava/util/concurrent/TimeUnit;) setMaximumPoolSize(I) setRejectedExecutionHandler(Ljava/util/concurrent/RejectedExecutionHandler;) setThreadFactory(Ljava/util/concurrent/ThreadFactory;) shutdown() shutdownNow() terminated() toString()",
	},
	"java/util/concurrent/ThreadPoolExecutor$AbortPolicy": {
		supers:  "java/util/concurrent/RejectedExecutionHandler",
		methods: "rejectedExecution(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)",
	},
	"java/util/concurrent/ThreadPoolExecutor$CallerRunsPolicy": {
		supers:  "java/util/concurrent/RejectedExecutionHandler",
		methods: "rejectedExecution(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)",
	},
	"java/util/concurrent/ThreadPoolExecutor$DiscardOldestPolicy": {
		supers:  "java/util/concurrent/RejectedExecutionHandler",
		methods: "rejectedExecution(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)",
	},
	"java/util/concurrent/ThreadPoolExecutor$DiscardPolicy": {
		supers:  "java/util/concurrent/RejectedExecutionHandler",
		methods: "rejectedExecution(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)",
	},
	"java/util/concurrent/TimeoutException": {
		supers: "java/lang/Exception",
	},
	"java/util/concurrent/TransferQueue": {
		supers:  "java/util/concurrent/BlockingQueue",
		methods: "getWaitingConsumerCount() hasWaitingConsumer() transfer(Ljava/lang/Object;) tryTransfer(Ljava/lang/Object;) tryTransfer(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;)",
	},
	"java/util/concurrent/atomic/AtomicBoolean": {
		supers:  "java/io/Serializable",
		methods: "toString() weakCompareAndSet(ZZ) weakCompareAndSetPlain(ZZ)",
	},
	"java/util/concurrent/atomic/AtomicInteger": {
		supers:  "java/lang/Number java/io/Serializable",
		methods: "doubleValue() floatValue() intValue() longValue() toString()",
	},
	"java/util/concurrent/atomic/AtomicIntegerArray": {
		supers:  "java/io/Serializable",
		methods: "toString()",
	},
	"java/util/concurrent/atomic/AtomicIntegerFieldUpdater": {
		methods: "addAndGet(Ljava/lang/Object;I) compareAndSet(Ljava/lang/Object;II) decrementAndGet(Ljava/lang/Object;) get(Ljava/lang/Object;) getAndAdd(Ljava/lang/Object;I) getAndDecrement(Ljava/lang/Object;) getAndIncrement(Ljava/lang/Object;) getAndSet(Ljava/lang/Object;I) incrementAndGet(Ljava/lang/Object;) lazySet(Ljava/lang/Object;I) set(Ljava/lang/Object;I) weakCompareAndSet(Ljava/lang/Object;II)",
	},
	"java/util/concurrent/atomic/AtomicLong": {
		supers:  "java/lang/Number java/io/Serializable",
		methods: "doubleValue() floatValue() intValue() longValue() toString()",
	},
	"java/util/concurrent/atomic/AtomicLongArray": {
		supers:  "java/io/Serializable",
		methods: "addAndGet(IJ) toString()",
	},
	"java/util/concurrent/atomic/AtomicLongFieldUpdater": {
		methods: "addAndGet(Ljava/lang/Object;J) compareAndSet(Ljava/lang/Object;JJ) decrementAndGet(Ljava/lang/Object;) get(Ljava/lang/Object;) getAndAdd(Ljava/lang/Object;J) getAndDecrement(Ljava/lang/Object;) getAndIncrement(Ljava/lang/Object;) getAndSet(Ljava/lang/Object;J) incrementAndGet(Ljava/lang/Object;) lazySet(Ljava/lang/Object;J) set(Ljava/lang/Object;J) weakCompareAndSet(Ljava/lang/Object;JJ)",
	},
	"java/util/concurrent/atomic/AtomicMarkableReference": {
		methods: "attemptMark(Ljava/lang/Object;Z) compareAndSet(Ljava/lang/Object;Ljava/lang/Object;ZZ) get([Z) getReference() isMarked() set(Ljava/lang/Object;Z) weakCompareAndSet(Ljava/lang/Object;Ljava/lang/Object;ZZ)",
	},
	"java/util/concurrent/atomic/AtomicReference": {
		supers:  "java/io/Serializable",
		methods: "toString()",
	},
	"java/util/concurrent/atomic/AtomicReferenceArray": {
		supers:  "java/io/Serializable",
		methods: "toString()",
	},
	"java/util/concurrent/atomic/AtomicReferenceFieldUpdater": {
		methods: "compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;) get(Ljava/lang/Object;) getAndSet(Ljava/lang/Object;Ljava/lang/Object;) lazySet(Ljava/lang/Object;Ljava/lang/Object;) set(Ljava/lang/Object;Ljava/lang/Object;) weakCompareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)",
	},
	"java/util/concurrent/atomic/AtomicStampedReference": {
		methods: "attemptStamp(Ljava/lang/Object;I) compareAndSet(Ljava/lang/Object;Ljava/lang/Object;II) get([I) getReference() getStamp() set(Ljava/lang/Object;I) weakCompareAndSet(Ljava/lang/Object;Ljava/lang/Object;II)",
	},
	"java/util/concurrent/atomic/DoubleAccumulator": {
		supers:  "java/util/concurrent/atomic/Striped64 java/io/Serializable",
		methods: "accumulate(D) doubleValue() floatValue() get() getThenReset() intValue() longValue() reset() toString()",
	},
	"java/util/concurrent/atomic/DoubleAdder": {
		supers:  "java/util/concurrent/atomic/Striped64 java/io/Serializable",
		methods: "add(D) doubleValue() floatValue() intValue() longValue() reset() sum() sumThenReset() toString()",
	},
	"java/util/concurrent/atomic/LongAccumulator": {
		supers:  "java/util/concurrent/atomic/Striped64 java/io/Serializable",
		methods: "accumulate(J) doubleValue() floatValue() get() getThenReset() intValue() longValue() reset() toString()",
	},
	"java/util/concurrent/atomic/LongAdder": {
		supers:  "java/util/concurrent/atomic/Striped64 java/io/Serializable",
		methods: "add(J) decrement() doubleValue() floatValue() increment() intValue() longValue() reset() sum() sumThenReset() toString()",
	},
	"java/util/concurrent/atomic/Striped64": {
		supers: "java/lang/Number",
	},
	"java/util/concurrent/locks/AbstractOwnableSynchronizer": {
		supers: "java/io/Serializable",
	},
	"java/util/concurrent/locks/AbstractQueuedLongSynchronizer": {
		supers:  "java/util/concurrent/locks/AbstractOwnableSynchronizer java/io/Serializable",
		methods: "isHeldExclusively() toString() tryAcquire(J) tryAcquireShared(J) tryRelease(J) tryReleaseShared(J)",
	},
	"java/util/concurrent/locks/AbstractQueuedLongSynchronizer$ConditionObject": {
		supers: "java/util/concurrent/locks/Condition java/io/Serializable",
	},
	"java/util/concurrent/locks/AbstractQueuedSynchronizer": {
		supers:  "java/util/concurrent/locks/AbstractOwnableSynchronizer java/io/Serializable",
		methods: "isHeldExclusively() toString() tryAcquire(I) tryAcquireShared(I) tryRelease(I) tryReleaseShared(I)",
	},
	"java/util/concurrent/locks/AbstractQueuedSynchronizer$ConditionObject": {
		supers: "java/util/concurrent/locks/Condition java/io/Serializable",
	},
	"java/util/concurrent/locks/Condition": {
		methods: "await() await(JLjava/util/concurrent/TimeUnit;) awaitNanos(J) awaitUninterruptibly() awaitUntil(Ljava/util/Date;) signal() signalAll()",
	},
	"java/util/concurrent/locks/Lock": {
		methods: "lock() lockInterruptibly() newCondition() tryLock() tryLock(JLjava/util/concurrent/TimeUnit;) unlock()",
	},
	"java/util/concurrent/locks/LockSupport": {},
	"java/util/concurrent/locks/ReadWriteLock": {
		methods: "readLock() writeLock()",
	},
	"java/util/concurrent/locks/ReentrantLock": {
		supers:  "java/util/concurrent/locks/Lock java/io/Serializable",
		methods: "getHoldCount() getOwner() getQueuedThreads() getWaitQueueLength(Ljava/util/concurrent/locks/Condition;) getWaitingThreads(Ljava/util/concurrent/locks/Condition;) hasWaiters(Ljava/util/concurrent/locks/Condition;) isHeldByCurrentThread() isLocked() lock() lockInterruptibly() newCondition() toString() tryLock() tryLock(JLjava/util/concurrent/TimeUnit;) unlock()",
	},
	"java/util/concurrent/locks/ReentrantReadWriteLock": {
		supers:  "java/util/concurrent/locks/ReadWriteLock java/io/Serializable",
		methods: "getOwner() getQueuedReaderThreads() getQueuedThreads() getQueuedWriterThreads() getReadHoldCount() getReadLockCount() getWaitQueueLength(Ljava/util/concurrent/locks/Condition;) getWaitingThreads(Ljava/util/concurrent/locks/Condition;) getWriteHoldCount() hasWaiters(Ljava/util/concurrent/locks/Condition;) isWriteLocked() isWriteLockedByCurrentThread() readLock() toString() writeLock()",
	},
	"java/util/concurrent/locks/ReentrantReadWriteLock$ReadLock": {
		supers:  "java/util/concurrent/locks/Lock java/io/Serializable",
		methods: "lock() lockInterruptibly() newCondition() toString() tryLock() tryLock(JLjava/util/concurrent/TimeUnit;) unlock()",
	},
	"java/util/concurrent/locks/ReentrantReadWriteLock$WriteLock": {
		supers:  "java/util/concurrent/locks/Lock java/io/Serializable",
		methods: "getHoldCount() isHeldByCurrentThread() lock() lockInterruptibly() newCondition() toString() tryLock() tryLock(JLjava/util/concurrent/TimeUnit;) unlock()",
	},
	"java/util/concurrent/locks/StampedLock": {
		supers:  "java/io/Serializable",
		methods: "asReadLock() asReadWriteLock() asWriteLock() getReadLockCount() isReadLocked() isWriteLocked() readLock() readLockInterruptibly() toString() tryConvertToOptimisticRead(J) tryConvertToReadLock(J) tryConvertToWriteLock(J) tryOptimisticRead() tryReadLock() tryReadLock(JLjava/util/concurrent/TimeUnit;) tryUnlockRead() tryUnlockWrite() tryWriteLock() tryWriteLock(JLjava/util/concurrent/TimeUnit;) unlock(J) unlockRead(J) unlockWrite(J) validate(J) writeLock() writeLockInterruptibly()",
	},
	"java/util/function/BiConsumer": {
		methods: "accept(Ljava/lang/Object;Ljava/lang/Object;) andThen(Ljava/util/function/BiConsumer;)",
	},
	"java/util/function/BiFunction": {
		methods: "andThen(Ljava/util/function/Function;) apply(Ljava/lang/Object;Ljava/lang/Object;)",
	},
	"java/util/function/BiPredicate": {
		methods: "and(Ljava/util/function/BiPredicate;) negate() or(Ljava/util/function/BiPredicate;) test(Ljava/lang/Object;Ljava/lang/Object;)",
	},
	"java/util/function/BinaryOperator": {
		supers: "java/util/function/BiFunction",
	},
	"java/util/function/BooleanSupplier": {
		methods: "getAsBoolean()",
	},
	"java/util/function/Consumer": {
		methods: "accept(Ljava/lang/Object;) andThen(Ljava/util/function/Consumer;)",
	},
	"java/util/function/DoubleBinaryOperator": {
		methods: "applyAsDouble(DD)",
	},
	"java/util/function/DoubleConsumer": {
		methods: "accept(D) andThen(Ljava/util/function/DoubleConsumer;)",
	},
	"java/util/function/DoubleFunction": {
		methods: "apply(D)",
	},
	"java/util/function/DoublePredicate": {
		methods: "and(Ljava/util/function/DoublePredicate;) negate() or(Ljava/util/function/DoublePredicate;) test(D)",
	},
	"java/util/function/DoubleSupplier": {
		methods: "getAsDouble()",
	},
	"java/util/function/DoubleToIntFunction": {
		methods: "applyAsInt(D)",
	},
	"java/util/function/DoubleToLongFunction": {
		methods: "applyAsLong(D)",
	},
	"java/util/function/DoubleUnaryOperator": {
		methods: "andThen(Ljava/util/function/DoubleUnaryOperator;) applyAsDouble(D) compose(Ljava/util/function/DoubleUnaryOperator;)",
	},
	"java/util/function/Function": {
		methods: "andThen(Ljava/util/function/Function;) apply(Ljava/lang/Object;) compose(Ljava/util/function/Function;)",
	},
	"java/util/function/IntBinaryOperator": {
		methods: "applyAsInt(II)",
	},
	"java/util/function/IntConsumer": {
		methods: "accept(I) andThen(Ljava/util/function/IntConsumer;)",
	},
	"java/util/function/IntFunction": {
		methods: "apply(I)",
	},
	"java/util/function/IntPredicate": {
		methods: "and(Ljava/util/function/IntPredicate;) negate() or(Ljava/util/function/IntPredicate;) test(I)",
	},
	"java/util/function/IntSupplier": {
		methods: "getAsInt()",
	},
	"java/util/function/IntToDoubleFunction": {
		methods: "applyAsDouble(I)",
	},
	"java/util/function/IntToLongFunction": {
		methods: "applyAsLong(I)",
	},
	"java/util/function/IntUnaryOperator": {
		methods: "andThen(Ljava/util/function/IntUnaryOperator;) applyAsInt(I) compose(Ljava/util/function/IntUnaryOperator;)",
	},
	"java/util/function/LongBinaryOperator": {
		methods: "applyAsLong(JJ)",
	},
	"java/util/function/LongConsumer": {
		methods: "accept(J) andThen(Ljava/util/function/LongConsumer;)",
	},
	"java/util/function/LongFunction": {
		methods: "apply(J)",
	},
	"java/util/function/LongPredicate": {
		methods: "and(Ljava/util/function/LongPredicate;) negate() or(Ljava/util/function/LongPredicate;) test(J)",
	},
	"java/util/function/LongSupplier": {
		methods: "getAsLong()",
	},
	"java/util/function/LongToDoubleFunction": {
		methods: "applyAsDouble(J)",
	},
	"java/util/function/LongToIntFunction": {
		methods: "applyAsInt(J)",
	},
	"java/util/function/LongUnaryOperator": {
		methods: "andThen(Ljava/util/function/LongUnaryOperator;) applyAsLong(J) compose(Ljava/util/function/LongUnaryOperator;)",
	},
	"java/util/function/ObjDoubleConsumer": {
		methods: "accept(Ljava/lang/Object;D)",
	},
	"java/util/function/ObjIntConsumer": {
		methods: "accept(Ljava/lang/Object;I)",
	},
	"java/util/function/ObjLongConsumer": {
		methods: "accept(Ljava/lang/Object;J)",
	},
	"java/util/function/Predicate": {
		methods: "and(Ljava/util/function/Predicate;) negate() or(Ljava/util/function/Predicate;) test(Ljava/lang/Object;)",
	},
	"java/util/function/Supplier": {
		methods: "get()",
	},
	"java/util/function/ToDoubleBiFunction": {
		methods: "applyAsDouble(Ljava/lang/Object;Ljava/lang/Object;)",
	},
	"java/util/function/ToDoubleFunction": {
		methods: "applyAsDouble(Ljava/lang/Object;)",
	},
	"java/util/function/ToIntBiFunction": {
		methods: "applyAsInt(Ljava/lang/Object;Ljava/lang/Object;)",
	},
	"java/util/function/ToIntFunction": {
		methods: "applyAsInt(Ljava/lang/Object;)",
	},
	"java/util/function/ToLongBiFunction": {
		methods: "applyAsLong(Ljava/lang/Object;Ljava/lang/Object;)",
	},
	"java/util/function/ToLongFunction": {
		methods: "applyAsLong(Ljava/lang/Object;)",
	},
	"java/util/function/UnaryOperator": {
		supers: "java/util/function/Function",
	},
	"java/util/jar/Attributes": {
		supers:  "java/util/Map java/lang/Cloneable",
		methods: "clear() clone() containsKey(Ljava/lang/Object;) containsValue(Ljava/lang/Object;) entrySet() equals(Ljava/lang/Object;) get(Ljava/lang/Object;) getValue(Ljava/lang/String;) getValue(Ljava/util/jar/Attributes$Name;) hashCode() isEmpty() keySet() put(Ljava/lang/Object;Ljava/lang/Object;) putAll(Ljava/util/Map;) putValue(Ljava/lang/String;Ljava/lang/String;) remove(Ljava/lang/Object;) size() values()",
	},
	"java/util/jar/Attributes$Name": {
		methods: "equals(Ljava/lang/Object;) hashCode() toString()",
	},
	"java/util/jar/JarEntry": {
		supers:  "java/util/zip/ZipEntry",
		methods: "getAttributes() getCertificates() getCodeSigners() getRealName()",
	},
	"java/util/jar/JarException": {
		supers: "java/util/zip/ZipException",
	},
	"java/util/jar/JarFile": {
		supers:  "java/util/zip/ZipFile",
		methods: "entries() getEntry(Ljava/lang/String;) getInputStream(Ljava/util/zip/ZipEntry;) getJarEntry(Ljava/lang/String;) getManifest() stream() versionedStream()",
	},
	"java/util/jar/JarInputStream": {
		supers:  "java/util/zip/ZipInputStream",
		methods: "createZipEntry(Ljava/lang/String;) getManifest() getNextEntry() getNextJarEntry() read([BII)",
	},
	"java/util/jar/JarOutputStream": {
		supers:  "java/util/zip/ZipOutputStream",
		methods: "putNextEntry(Ljava/util/zip/ZipEntry;)",
	},
	"java/util/jar/Manifest": {
		supers:  "java/lang/Cloneable",
		methods: "clear() clone() equals(Ljava/lang/Object;) getAttributes(Ljava/lang/String;) getEntries() getMainAttributes() hashCode() read(Ljava/io/InputStream;) write(Ljava/io/OutputStream;)",
	},
	"java/util/random/RandomGenerator": {
		methods: "doubles() doubles(DD) doubles(J) doubles(JDD) ints() ints(II) ints(J) ints(JII) isDeprecated() longs() longs(J) longs(JJ) longs(JJJ) nextBoolean() nextBytes([B) nextDouble() nextDouble(D) nextDouble(DD) nextExponential() nextFloat() nextFloat(F) nextFloat(FF) nextGaussian() nextGaussian(DD) nextInt() nextInt(I) nextInt(II) nextLong() nextLong(J) nextLong(JJ)",
	},
	"java/util/random/RandomGenerator$ArbitrarilyJumpableGenerator": {
		supers:  "java/util/random/RandomGenerator$LeapableGenerator",
		methods: "copy() copyAndJump(D) jump() jump(D) jumpPowerOfTwo(I) jumps(D) jumps(JD) leap()",
	},
	"java/util/random/RandomGenerator$JumpableGenerator": {
		supers:  "java/util/random/RandomGenerator$StreamableGenerator",
		methods: "copy() copyAndJump() jump() jumpDistance() jumps() jumps(J) rngs() rngs(J)",
	},
	"java/util/random/RandomGenerator$LeapableGenerator": {
		supers:  "java/util/random/RandomGenerator$JumpableGenerator",
		methods: "copy() copyAndLeap() leap() leapDistance() leaps() leaps(J)",
	},
	"java/util/random/RandomGenerator$SplittableGenerator": {
		supers:  "java/util/random/RandomGenerator$StreamableGenerator",
		methods: "rngs() rngs(J) split() split(Ljava/util/random/RandomGenerator$SplittableGenerator;) splits() splits(J) splits(JLjava/util/random/RandomGenerator$SplittableGenerator;) splits(Ljava/util/random/RandomGenerator$SplittableGenerator;)",
	},
	"java/util/random/RandomGenerator$StreamableGenerator": {
		supers:  "java/util/random/RandomGenerator",
		methods: "rngs() rngs(J)",
	},
	"java/util/regex/MatchResult": {
		methods: "end() end(I) end(Ljava/lang/String;) group() group(I) group(Ljava/lang/String;) groupCount() hasMatch() namedGroups() start() start(I) start(Ljava/lang/String;)",
	},
	"java/util/regex/PatternSyntaxException": {
		supers:  "java/lang/IllegalArgumentException",
		methods: "getDescription() getIndex() getMessage() getPattern()",
	},
	"java/util/spi/AbstractResourceBundleProvider": {
		supers:  "java/util/spi/ResourceBundleProvider",
		methods: "getBundle(Ljava/lang/String;Ljava/util/Locale;) toBundleName(Ljava/lang/String;Ljava/util/Locale;)",
	},
	"java/util/spi/CalendarDataProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getFirstDayOfWeek(Ljava/util/Locale;) getMinimalDaysInFirstWeek(Ljava/util/Locale;)",
	},
	"java/util/spi/CalendarNameProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getDisplayName(Ljava/lang/String;IIILjava/util/Locale;) getDisplayNames(Ljava/lang/String;IILjava/util/Locale;)",
	},
	"java/util/spi/CurrencyNameProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getDisplayName(Ljava/lang/String;Ljava/util/Locale;) getSymbol(Ljava/lang/String;Ljava/util/Locale;)",
	},
	"java/util/spi/LocaleNameProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getDisplayCountry(Ljava/lang/String;Ljava/util/Locale;) getDisplayLanguage(Ljava/lang/String;Ljava/util/Locale;) getDisplayScript(Ljava/lang/String;Ljava/util/Locale;) getDisplayUnicodeExtensionKey(Ljava/lang/String;Ljava/util/Locale;) getDisplayUnicodeExtensionType(Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;) getDisplayVariant(Ljava/lang/String;Ljava/util/Locale;)",
	},
	"java/util/spi/LocaleServiceProvider": {
		methods: "getAvailableLocales() isSupportedLocale(Ljava/util/Locale;)",
	},
	"java/util/spi/ResourceBundleControlProvider": {
		methods: "getControl(Ljava/lang/String;)",
	},
	"java/util/spi/ResourceBundleProvider": {
		methods: "getBundle(Ljava/lang/String;Ljava/util/Locale;)",
	},
	"java/util/spi/TimeZoneNameProvider": {
		supers:  "java/util/spi/LocaleServiceProvider",
		methods: "getDisplayName(Ljava/lang/String;ZILjava/util/Locale;) getGenericDisplayName(Ljava/lang/String;ILjava/util/Locale;)",
	},
	"java/util/spi/ToolProvider": {
		methods: "description() name() run(Ljava/io/PrintStream;Ljava/io/PrintStream;[Ljava/lang/String;) run(Ljava/io/PrintWriter;Ljava/io/PrintWriter;[Ljava/lang/String;)",
	},
	"java/util/stream/BaseStream": {
		supers:  "java/lang/AutoCloseable",
		methods: "close() isParallel() iterator() onClose(Ljava/lang/Runnable;) parallel() sequential() spliterator() unordered()",
	},
	"java/util/stream/Collector": {
		methods: "accumulator() characteristics() combiner() finisher() supplier()",
	},
	"java/util/stream/DoubleStream": {
		supers:  "java/util/stream/BaseStream",
		methods: "allMatch(Ljava/util/function/DoublePredicate;) anyMatch(Ljava/util/function/DoublePredicate;) average() boxed() collect(Ljava/util/function/Supplier;Ljava/util/function/ObjDoubleConsumer;Ljava/util/function/BiConsumer;) count() distinct() dropWhile(Ljava/util/function/DoublePredicate;) filter(Ljava/util/function/DoublePredicate;) findAny() findFirst() flatMap(Ljava/util/function/DoubleFunction;) forEach(Ljava/util/function/DoubleConsumer;) forEachOrdered(Ljava/util/function/DoubleConsumer;) iterator() limit(J) map(Ljava/util/function/DoubleUnaryOperator;) mapMulti(Ljava/util/stream/DoubleStream$DoubleMapMultiConsumer;) mapToInt(Ljava/util/function/DoubleToIntFunction;) mapToLong(Ljava/util/function/DoubleToLongFunction;) mapToObj(Ljava/util/function/DoubleFunction;) max() min() noneMatch(Ljava/util/function/DoublePredicate;) parallel() peek(Ljava/util/function/DoubleConsumer;) reduce(DLjava/util/function/DoubleBinaryOperator;) reduce(Ljava/util/function/DoubleBinaryOperator;) sequential() skip(J) sorted() spliterator() sum() summaryStatistics() takeWhile(Ljava/util/function/DoublePredicate;) toArray()",
	},
	"java/util/stream/DoubleStream$Builder": {
		supers:  "java/util/function/DoubleConsumer",
		methods: "accept(D) add(D) build()",
	},
	"java/util/stream/DoubleStream$DoubleMapMultiConsumer": {
		methods: "accept(DLjava/util/function/DoubleConsumer;)",
	},
	"java/util/stream/IntStream": {
		supers:  "java/util/stream/BaseStream",
		methods: "allMatch(Ljava/util/function/IntPredicate;) anyMatch(Ljava/util/function/IntPredicate;) asDoubleStream() asLongStream() average() boxed() collect(Ljava/util/function/Supplier;Ljava/util/function/ObjIntConsumer;Ljava/util/function/BiConsumer;) count() distinct() dropWhile(Ljava/util/function/IntPredicate;) filter(Ljava/util/function/IntPredicate;) findAny() findFirst() flatMap(Ljava/util/function/IntFunction;) forEach(Ljava/util/function/IntConsumer;) forEachOrdered(Ljava/util/function/IntConsumer;) iterator() limit(J) map(Ljava/util/function/IntUnaryOperator;) mapMulti(Ljava/util/stream/IntStream$IntMapMultiConsumer;) mapToDouble(Ljava/util/function/IntToDoubleFunction;) mapToLong(Ljava/util/function/IntToLongFunction;) mapToObj(Ljava/util/function/IntFunction;) max() min() noneMatch(Ljava/util/function/IntPredicate;) parallel() peek(Ljava/util/function/IntConsumer;) reduce(ILjava/util/function/IntBinaryOperator;) reduce(Ljava/util/function/IntBinaryOperator;) sequential() skip(J) sorted() spliterator() sum() summaryStatistics() takeWhile(Ljava/util/function/IntPredicate;) toArray()",
	},
	"java/util/stream/IntStream$Builder": {
		supers:  "java/util/function/IntConsumer",
		methods: "accept(I) add(I) build()",
	},
	"java/util/stream/IntStream$IntMapMultiConsumer": {
		methods: "accept(ILjava/util/function/IntConsumer;)",
	},
	"java/util/stream/LongStream": {
		supers:  "java/util/stream/BaseStream",
		methods: "allMatch(Ljava/util/function/LongPredicate;) anyMatch(Ljava/util/function/LongPredicate;) asDoubleStream() average() boxed() collect(Ljava/util/function/Supplier;Ljava/util/function/ObjLongConsumer;Ljava/util/function/BiConsumer;) count() distinct() dropWhile(Ljava/util/function/LongPredicate;) filter(Ljava/util/function/LongPredicate;) findAny() findFirst() flatMap(Ljava/util/function/LongFunction;) forEach(Ljava/util/function/LongConsumer;) forEachOrdered(Ljava/util/function/LongConsumer;) iterator() limit(J) map(Ljava/util/function/LongUnaryOperator;) mapMulti(Ljava/util/stream/LongStream$LongMapMultiConsumer;) mapToDouble(Ljava/util/function/LongToDoubleFunction;) mapToInt(Ljava/util/function/LongToIntFunction;) mapToObj(Ljava/util/function/LongFunction;) max() min() noneMatch(Ljava/util/function/LongPredicate;) parallel() peek(Ljava/util/function/LongConsumer;) reduce(JLjava/util/function/LongBinaryOperator;) reduce(Ljava/util/function/LongBinaryOperator;) sequential() skip(J) sorted() spliterator() sum() summaryStatistics() takeWhile(Ljava/util/function/LongPredicate;) toArray()",
	},
	"java/util/stream/LongStream$Builder": {
		supers:  "java/util/function/LongConsumer",
		methods: "accept(J) add(J) build()",
	},
	"java/util/stream/LongStream$LongMapMultiConsumer": {
		methods: "accept(JLjava/util/function/LongConsumer;)",
	},
	"java/util/stream/Node": {
		methods: "asArray(Ljava/util/function/IntFunction;) copyInto([Ljava/lang/Object;I) count() forEach(Ljava/util/function/Consumer;) getChild(I) getChildCount() getShape() spliterator() truncate(JJLjava/util/function/IntFunction;)",
	},
	"java/util/stream/Node$Builder": {
		supers:  "java/util/stream/Sink",
		methods: "build()",
	},
	"java/util/stream/Node$Builder$OfDouble": {
		supers:  "java/util/stream/Node$Builder java/util/stream/Sink$OfDouble",
		methods: "build()",
	},
	"java/util/stream/Node$Builder$OfInt": {
		supers:  "java/util/stream/Node$Builder java/util/stream/Sink$OfInt",
		methods: "build()",
	},
	"java/util/stream/Node$Builder$OfLong": {
		supers:  "java/util/stream/Node$Builder java/util/stream/Sink$OfLong",
		methods: "build()",
	},
	"java/util/stream/Node$OfDouble": {
		supers:  "java/util/stream/Node$OfPrimitive",
		methods: "copyInto([Ljava/lang/Double;I) copyInto([Ljava/lang/Object;I) forEach(Ljava/util/function/Consumer;) getShape() newArray(I) truncate(JJLjava/util/function/IntFunction;)",
	},
	"java/util/stream/Node$OfInt": {
		supers:  "java/util/stream/Node$OfPrimitive",
		methods: "copyInto([Ljava/lang/Integer;I) copyInto([Ljava/lang/Object;I) forEach(Ljava/util/function/Consumer;) getShape() newArray(I) truncate(JJLjava/util/function/IntFunction;)",
	},
	"java/util/stream/Node$OfLong": {
		supers:  "java/util/stream/Node$OfPrimitive",
		methods: "copyInto([Ljava/lang/Long;I) copyInto([Ljava/lang/Object;I) forEach(Ljava/util/function/Consumer;) getShape() newArray(I) truncate(JJLjava/util/function/IntFunction;)",
	},
	"java/util/stream/Node$OfPrimitive": {
		supers:  "java/util/stream/Node",
		methods: "asArray(Ljava/util/function/IntFunction;) asPrimitiveArray() copyInto(Ljava/lang/Object;I) forEach(Ljava/lang/Object;) getChild(I) newArray(I) spliterator() truncate(JJLjava/util/function/IntFunction;)",
	},
	"java/util/stream/Sink": {
		supers:  "java/util/function/Consumer",
		methods: "accept(D) accept(I) accept(J) begin(J) cancellationRequested() end()",
	},
	"java/util/stream/Sink$ChainedDouble": {
		supers:  "java/util/stream/Sink$OfDouble",
		methods: "begin(J) cancellationRequested() end()",
	},
	"java/util/stream/Sink$ChainedInt": {
		supers:  "java/util/stream/Sink$OfInt",
		methods: "begin(J) cancellationRequested() end()",
	},
	"java/util/stream/Sink$ChainedLong": {
		supers:  "java/util/stream/Sink$OfLong",
		methods: "begin(J) cancellationRequested() end()",
	},
	"java/util/stream/Sink$ChainedReference": {
		supers:  "java/util/stream/Sink",
		methods: "begin(J) cancellationRequested() end()",
	},
	"java/util/stream/Sink$OfDouble": {
		supers:  "java/util/stream/Sink java/util/function/DoubleConsumer",
		methods: "accept(D) accept(Ljava/lang/Double;) accept(Ljava/lang/Object;)",
	},
	"java/util/stream/Sink$OfInt": {
		supers:  "java/util/stream/Sink java/util/function/IntConsumer",
		methods: "accept(I) accept(Ljava/lang/Integer;) accept(Ljava/lang/Object;)",
	},
	"java/util/stream/Sink$OfLong": {
		supers:  "java/util/stream/Sink java/util/function/LongConsumer",
		methods: "accept(J) accept(Ljava/lang/Long;) accept(Ljava/lang/Object;)",
	},
	"java/util/stream/Stream": {
		supers:  "java/util/stream/BaseStream",
		methods: "allMatch(Ljava/util/function/Predicate;) anyMatch(Ljava/util/function/Predicate;) collect(Ljava/util/function/Supplier;Ljava/util/function/BiConsumer;Ljava/util/function/BiConsumer;) collect(Ljava/util/stream/Collector;) count() distinct() dropWhile(Ljava/util/function/Predicate;) filter(Ljava/util/function/Predicate;) findAny() findFirst() flatMap(Ljava/util/function/Function;) flatMapToDouble(Ljava/util/function/Function;) flatMapToInt(Ljava/util/function/Function;) flatMapToLong(Ljava/util/function/Function;) forEach(Ljava/util/function/Consumer;) forEachOrdered(Ljava/util/function/Consumer;) limit(J) map(Ljava/util/function/Function;) mapMulti(Ljava/util/function/BiConsumer;) mapMultiToDouble(Ljava/util/function/BiConsumer;) mapMultiToInt(Ljava/util/function/BiConsumer;) mapMultiToLong(Ljava/util/function/BiConsumer;) mapToDouble(Ljava/util/function/ToDoubleFunction;) mapToInt(Ljava/util/function/ToIntFunction;) mapToLong(Ljava/util/function/ToLongFunction;) max(Ljava/util/Comparator;) min(Ljava/util/Comparator;) noneMatch(Ljava/util/function/Predicate;) peek(Ljava/util/function/Consumer;) reduce(Ljava/lang/Object;Ljava/util/function/BiFunction;Ljava/util/function/BinaryOperator;) reduce(Ljava/lang/Object;Ljava/util/function/BinaryOperator;) reduce(Ljava/util/function/BinaryOperator;) skip(J) sorted() sorted(Ljava/util/Comparator;) takeWhile(Ljava/util/function/Predicate;) toArray() toArray(Ljava/util/function/IntFunction;) toList()",
	},
	"java/util/stream/Stream$Builder": {
		supers:  "java/util/function/Consumer",
		methods: "accept(Ljava/lang/Object;) add(Ljava/lang/Object;) build()",
	},
	"java/util/zip/Adler32": {
		supers:  "java/util/zip/Checksum",
		methods: "getValue() reset() update(I) update(Ljava/nio/ByteBuffer;) update([BII)",
	},
	"java/util/zip/CRC32": {
		supers:  "java/util/zip/Checksum",
		methods: "getValue() reset() update(I) update(Ljava/nio/ByteBuffer;) update([BII)",
	},
	"java/util/zip/CheckedInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "getChecksum() read() read([BII) skip(J)",
	},
	"java/util/zip/CheckedOutputStream": {
		supers:  "java/io/FilterOutputStream",
		methods: "getChecksum() write(I) write([BII)",
	},
	"java/util/zip/Checksum": {
		methods: "getValue() reset() update(I) update(Ljava/nio/ByteBuffer;) update([B) update([BII)",
	},
	"java/util/zip/DataFormatException": {
		supers: "java/lang/Exception",
	},
	"java/util/zip/Deflater": {
		methods: "deflate(Ljava/nio/ByteBuffer;) deflate(Ljava/nio/ByteBuffer;I) deflate([B) deflate([BII) deflate([BIII) end() finish() finished() getAdler() getBytesRead() getBytesWritten() getTotalIn() getTotalOut() needsInput() reset() setDictionary(Ljava/nio/ByteBuffer;) setDictionary([B) setDictionary([BII) setInput(Ljava/nio/ByteBuffer;) setInput([B) setInput([BII) setLevel(I) setStrategy(I)",
	},
	"java/util/zip/DeflaterInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "available() close() mark(I) markSupported() read() read([BII) reset() skip(J)",
	},
	"java/util/zip/DeflaterOutputStream": {
		supers:  "java/io/FilterOutputStream",
		methods: "close() deflate() finish() flush() write(I) write([BII)",
	},
	"java/util/zip/GZIPInputStream": {
		supers:  "java/util/zip/InflaterInputStream",
		methods: "close() read([BII)",
	},
	"java/util/zip/GZIPOutputStream": {
		supers:  "java/util/zip/DeflaterOutputStream",
		methods: "finish() write([BII)",
	},
	"java/util/zip/Inflater": {
		methods: "end() finished() getAdler() getBytesRead() getBytesWritten() getRemaining() getTotalIn() getTotalOut() inflate(Ljava/nio/ByteBuffer;) inflate([B) inflate([BII) needsDictionary() needsInput() reset() setDictionary(Ljava/nio/ByteBuffer;) setDictionary([B) setDictionary([BII) setInput(Ljava/nio/ByteBuffer;) setInput([B) setInput([BII)",
	},
	"java/util/zip/InflaterInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "available() close() fill() mark(I) markSupported() read() read([BII) reset() skip(J)",
	},
	"java/util/zip/InflaterOutputStream": {
		supers:  "java/io/FilterOutputStream",
		methods: "close() finish() flush() write(I) write([BII)",
	},
	"java/util/zip/ZipConstants": {},
	"java/util/zip/ZipEntry": {
		supers:  "java/util/zip/ZipConstants java/lang/Cloneable",
		methods: "clone() getComment() getCompressedSize() getCrc() getCreationTime() getExtra() getLastAccessTime() getLastModifiedTime() getMethod() getName() getSize() getTime() getTimeLocal() hashCode() isDirectory() setComment(Ljava/lang/String;) setCompressedSize(J) setCrc(J) setCreationTime(Ljava/nio/file/attribute/FileTime;) setExtra([B) setLastAccessTime(Ljava/nio/file/attribute/FileTime;) setLastModifiedTime(Ljava/nio/file/attribute/FileTime;) setMethod(I) setSize(J) setTime(J) setTimeLocal(Ljava/time/LocalDateTime;) toString()",
	},
	"java/util/zip/ZipError": {
		supers: "java/lang/InternalError",
	},
	"java/util/zip/ZipException": {
		supers: "java/io/IOException",
	},
	"java/util/zip/ZipFile": {
		supers:  "java/util/zip/ZipConstants java/io/Closeable",
		methods: "close() entries() getComment() getEntry(Ljava/lang/String;) getInputStream(Ljava/util/zip/ZipEntry;) getName() size() stream()",
	},
	"java/util/zip/ZipInputStream": {
		supers:  "java/util/zip/InflaterInputStream java/util/zip/ZipConstants",
		methods: "available() close() closeEntry() createZipEntry(Ljava/lang/String;) getNextEntry() read() read([BII) readAllBytes() readNBytes(I) readNBytes([BII) skip(J) skipNBytes(J) transferTo(Ljava/io/OutputStream;)",
	},
	"java/util/zip/ZipOutputStream": {
		supers:  "java/util/zip/DeflaterOutputStream java/util/zip/ZipConstants",
		methods: "close() closeEntry() finish() putNextEntry(Ljava/util/zip/ZipEntry;) setComment(Ljava/lang/String;) setLevel(I) setMethod(I) write([BII)",
	},
	"javax/crypto/AEADBadTagException": {
		supers: "javax/crypto/BadPaddingException",
	},
	"javax/crypto/BadPaddingException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/crypto/Cipher": {
		methods: "toString()",
	},
	"javax/crypto/CipherInputStream": {
		supers:  "java/io/FilterInputStream",
		methods: "available() close() markSupported() read() read([B) read([BII) skip(J)",
	},
	"javax/crypto/CipherOutputStream": {
		supers:  "java/io/FilterOutputStream",
		methods: "close() flush() write(I) write([B) write([BII)",
	},
	"javax/crypto/CipherSpi": {
		methods: "engineDoFinal(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;) engineDoFinal([BII) engineDoFinal([BII[BI) engineGetBlockSize() engineGetIV() engineGetKeySize(Ljava/security/Key;) engineGetOutputSize(I) engineGetParameters() engineInit(ILjava/security/Key;Ljava/security/AlgorithmParameters;Ljava/security/SecureRandom;) engineInit(ILjava/security/Key;Ljava/security/SecureRandom;) engineInit(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;) engineSetMode(Ljava/lang/String;) engineSetPadding(Ljava/lang/String;) engineUnwrap([BLjava/lang/String;I) engineUpdate(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;) engineUpdate([BII) engineUpdate([BII[BI) engineUpdateAAD(Ljava/nio/ByteBuffer;) engineUpdateAAD([BII) engineWrap(Ljava/security/Key;)",
	},
	"javax/crypto/DecapsulateException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/crypto/EncryptedPrivateKeyInfo": {
		methods: "getAlgName() getAlgParameters() getEncoded() getEncryptedData() getKeySpec(Ljava/security/Key;) getKeySpec(Ljava/security/Key;Ljava/lang/String;) getKeySpec(Ljava/security/Key;Ljava/security/Provider;) getKeySpec(Ljavax/crypto/Cipher;)",
	},
	"javax/crypto/ExemptionMechanism": {},
	"javax/crypto/ExemptionMechanismException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/crypto/ExemptionMechanismSpi": {
		methods: "engineGenExemptionBlob() engineGenExemptionBlob([BI) engineGetOutputSize(I) engineInit(Ljava/security/Key;) engineInit(Ljava/security/Key;Ljava/security/AlgorithmParameters;) engineInit(Ljava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)",
	},
	"javax/crypto/IllegalBlockSizeException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/crypto/KEMSpi": {
		methods: "engineNewDecapsulator(Ljava/security/PrivateKey;Ljava/security/spec/AlgorithmParameterSpec;) engineNewEncapsulator(Ljava/security/PublicKey;Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)",
	},
	"javax/crypto/KEMSpi$DecapsulatorSpi": {
		methods: "engineDecapsulate([BIILjava/lang/String;) engineEncapsulationSize() engineSecretSize()",
	},
	"javax/crypto/KEMSpi$EncapsulatorSpi": {
		methods: "engineEncapsulate(IILjava/lang/String;) engineEncapsulationSize() engineSecretSize()",
	},
	"javax/crypto/KeyAgreement": {},
	"javax/crypto/KeyAgreementSpi": {
		methods: "engineDoPhase(Ljava/security/Key;Z) engineGenerateSecret() engineGenerateSecret(Ljava/lang/String;) engineGenerateSecret([BI) engineInit(Ljava/security/Key;Ljava/security/SecureRandom;) engineInit(Ljava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)",
	},
	"javax/crypto/KeyGenerator": {},
	"javax/crypto/KeyGeneratorSpi": {
		methods: "engineGenerateKey() engineInit(ILjava/security/SecureRandom;) engineInit(Ljava/security/SecureRandom;) engineInit(Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)",
	},
	"javax/crypto/Mac": {
		supers: "java/lang/Cloneable",
	},
	"javax/crypto/MacSpi": {
		methods: "clone() engineDoFinal() engineGetMacLength() engineInit(Ljava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;) engineReset() engineUpdate(B) engineUpdate(Ljava/nio/ByteBuffer;) engineUpdate([BII)",
	},
	"javax/crypto/NoSuchPaddingException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/crypto/NullCipher": {
		supers: "javax/crypto/Cipher",
	},
	"javax/crypto/SealedObject": {
		supers: "java/io/Serializable",
	},
	"javax/crypto/SecretKey": {
		supers: "java/security/Key javax/security/auth/Destroyable",
	},
	"javax/crypto/SecretKeyFactory": {},
	"javax/crypto/SecretKeyFactorySpi": {
		methods: "engineGenerateSecret(Ljava/security/spec/KeySpec;) engineGetKeySpec(Ljavax/crypto/SecretKey;Ljava/lang/Class;) engineTranslateKey(Ljavax/crypto/SecretKey;)",
	},
	"javax/crypto/ShortBufferException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/crypto/interfaces/DHKey": {
		methods: "getParams()",
	},
	"javax/crypto/interfaces/DHPrivateKey": {
		supers:  "javax/crypto/interfaces/DHKey java/security/PrivateKey",
		methods: "getX()",
	},
	"javax/crypto/interfaces/DHPublicKey": {
		supers:  "javax/crypto/interfaces/DHKey java/security/PublicKey",
		methods: "getY()",
	},
	"javax/crypto/interfaces/PBEKey": {
		supers:  "javax/crypto/SecretKey",
		methods: "getIterationCount() getPassword() getSalt()",
	},
	"javax/crypto/spec/DESKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getKey()",
	},
	"javax/crypto/spec/DESedeKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getKey()",
	},
	"javax/crypto/spec/DHGenParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getExponentSize() getPrimeSize()",
	},
	"javax/crypto/spec/DHParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getG() getL() getP()",
	},
	"javax/crypto/spec/DHPrivateKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getG() getP() getX()",
	},
	"javax/crypto/spec/DHPublicKeySpec": {
		supers:  "java/security/spec/KeySpec",
		methods: "getG() getP() getY()",
	},
	"javax/crypto/spec/GCMParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getIV() getTLen()",
	},
	"javax/crypto/spec/IvParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getIV()",
	},
	"javax/crypto/spec/OAEPParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getDigestAlgorithm() getMGFAlgorithm() getMGFParameters() getPSource()",
	},
	"javax/crypto/spec/PBEKeySpec": {
		supers: "java/security/spec/KeySpec",
	},
	"javax/crypto/spec/PBEParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "getIterationCount() getParameterSpec() getSalt()",
	},
	"javax/crypto/spec/PSource": {
		methods: "getAlgorithm()",
	},
	"javax/crypto/spec/RC2ParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "equals(Ljava/lang/Object;) getEffectiveKeyBits() getIV() hashCode()",
	},
	"javax/crypto/spec/RC5ParameterSpec": {
		supers:  "java/security/spec/AlgorithmParameterSpec",
		methods: "equals(Ljava/lang/Object;) getIV() getRounds() getVersion() getWordSize() hashCode()",
	},
	"javax/crypto/spec/SecretKeySpec": {
		supers:  "java/security/spec/KeySpec javax/crypto/SecretKey",
		methods: "equals(Ljava/lang/Object;) getAlgorithm() getEncoded() getFormat() hashCode()",
	},
	"javax/net/ServerSocketFactory": {
		methods: "createServerSocket() createServerSocket(I) createServerSocket(II) createServerSocket(IILjava/net/InetAddress;)",
	},
	"javax/net/SocketFactory": {
		methods: "createSocket() createSocket(Ljava/lang/String;I) createSocket(Ljava/lang/String;ILjava/net/InetAddress;I) createSocket(Ljava/net/InetAddress;I) createSocket(Ljava/net/InetAddress;ILjava/net/InetAddress;I)",
	},
	"javax/net/ssl/CertPathTrustManagerParameters": {
		supers:  "javax/net/ssl/ManagerFactoryParameters",
		methods: "getParameters()",
	},
	"javax/net/ssl/ExtendedSSLSession": {
		supers:  "javax/net/ssl/SSLSession",
		methods: "getLocalSupportedSignatureAlgorithms() getPeerSupportedSignatureAlgorithms() getRequestedServerNames() getStatusResponses()",
	},
	"javax/net/ssl/HandshakeCompletedEvent": {
		supers:  "java/util/EventObject",
		methods: "getCipherSuite() getLocalCertificates() getLocalPrincipal() getPeerCertificateChain() getPeerCertificates() getPeerPrincipal() getSession() getSocket()",
	},
	"javax/net/ssl/HandshakeCompletedListener": {
		supers:  "java/util/EventListener",
		methods: "handshakeCompleted(Ljavax/net/ssl/HandshakeCompletedEvent;)",
	},
	"javax/net/ssl/HostnameVerifier": {
		methods: "verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)",
	},
	"javax/net/ssl/HttpsURLConnection": {
		supers:  "java/net/HttpURLConnection",
		methods: "getCipherSuite() getHostnameVerifier() getLocalCertificates() getLocalPrincipal() getPeerPrincipal() getSSLSession() getSSLSocketFactory() getServerCertificates() setHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;) setSSLSocketFactory(Ljavax/net/ssl/SSLSocketFactory;)",
	},
	"javax/net/ssl/KeyManager":        {},
	"javax/net/ssl/KeyManagerFactory": {},
	"javax/net/ssl/KeyManagerFactorySpi": {
		methods: "engineGetKeyManagers() engineInit(Ljava/security/KeyStore;[C) engineInit(Ljavax/net/ssl/ManagerFactoryParameters;)",
	},
	"javax/net/ssl/KeyStoreBuilderParameters": {
		supers:  "javax/net/ssl/ManagerFactoryParameters",
		methods: "getParameters()",
	},
	"javax/net/ssl/ManagerFactoryParameters": {},
	"javax/net/ssl/SNIMatcher": {
		methods: "matches(Ljavax/net/ssl/SNIServerName;)",
	},
	"javax/net/ssl/SNIServerName": {
		methods: "equals(Ljava/lang/Object;) hashCode() toString()",
	},
	"javax/net/ssl/SSLContext": {},
	"javax/net/ssl/SSLContextSpi": {
		methods: "engineCreateSSLEngine() engineCreateSSLEngine(Ljava/lang/String;I) engineGetClientSessionContext() engineGetDefaultSSLParameters() engineGetServerSessionContext() engineGetServerSocketFactory() engineGetSocketFactory() engineGetSupportedSSLParameters() engineInit([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)",
	},
	"javax/net/ssl/SSLEngine": {
		methods: "beginHandshake() closeInbound() closeOutbound() getApplicationProtocol() getDelegatedTask() getEnableSessionCreation() getEnabledCipherSuites() getEnabledProtocols() getHandshakeApplicationProtocol() getHandshakeApplicationProtocolSelector() getHandshakeSession() getHandshakeStatus() getNeedClientAuth() getPeerHost() getPeerPort() getSSLParameters() getSession() getSupportedCipherSuites() getSupportedProtocols() getUseClientMode() getWantClientAuth() isInboundDone() isOutboundDone() setEnableSessionCreation(Z) setEnabledCipherSuites([Ljava/lang/String;) setEnabledProtocols([Ljava/lang/String;) setHandshakeApplicationProtocolSelector(Ljava/util/function/BiFunction;) setNeedClientAuth(Z) setSSLParameters(Ljavax/net/ssl/SSLParameters;) setUseClientMode(Z) setWantClientAuth(Z) unwrap(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;) unwrap(Ljava/nio/ByteBuffer;[Ljava/nio/ByteBuffer;) unwrap(Ljava/nio/ByteBuffer;[Ljava/nio/ByteBuffer;II) wrap(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;) wrap([Ljava/nio/ByteBuffer;IILjava/nio/ByteBuffer;) wrap([Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)",
	},
	"javax/net/ssl/SSLEngineResult": {
		methods: "toString()",
	},
	"javax/net/ssl/SSLException": {
		supers: "java/io/IOException",
	},
	"javax/net/ssl/SSLHandshakeException": {
		supers: "javax/net/ssl/SSLException",
	},
	"javax/net/ssl/SSLKeyException": {
		supers: "javax/net/ssl/SSLException",
	},
	"javax/net/ssl/SSLParameters": {
		methods: "getAlgorithmConstraints() getApplicationProtocols() getCipherSuites() getEnableRetransmissions() getEndpointIdentificationAlgorithm() getMaximumPacketSize() getNamedGroups() getNeedClientAuth() getProtocols() getSignatureSchemes() getWantClientAuth() setAlgorithmConstraints(Ljava/security/AlgorithmConstraints;) setApplicationProtocols([Ljava/lang/String;) setCipherSuites([Ljava/lang/String;) setEnableRetransmissions(Z) setEndpointIdentificationAlgorithm(Ljava/lang/String;) setMaximumPacketSize(I) setNamedGroups([Ljava/lang/String;) setNeedClientAuth(Z) setProtocols([Ljava/lang/String;) setSignatureSchemes([Ljava/lang/String;) setWantClientAuth(Z)",
	},
	"javax/net/ssl/SSLPeerUnverifiedException": {
		supers: "javax/net/ssl/SSLException",
	},
	"javax/net/ssl/SSLProtocolException": {
		supers: "javax/net/ssl/SSLException",
	},
	"javax/net/ssl/SSLServerSocket": {
		supers:  "java/net/ServerSocket",
		methods: "getEnableSessionCreation() getEnabledCipherSuites() getEnabledProtocols() getNeedClientAuth() getSSLParameters() getSupportedCipherSuites() getSupportedProtocols() getUseClientMode() getWantClientAuth() setEnableSessionCreation(Z) setEnabledCipherSuites([Ljava/lang/String;) setEnabledProtocols([Ljava/lang/String;) setNeedClientAuth(Z) setSSLParameters(Ljavax/net/ssl/SSLParameters;) setUseClientMode(Z) setWantClientAuth(Z)",
	},
	"javax/net/ssl/SSLServerSocketFactory": {
		supers:  "javax/net/ServerSocketFactory",
		methods: "getDefaultCipherSuites() getSupportedCipherSuites()",
	},
	"javax/net/ssl/SSLSession": {
		methods: "getApplicationBufferSize() getCipherSuite() getCreationTime() getId() getLastAccessedTime() getLocalCertificates() getLocalPrincipal() getPacketBufferSize() getPeerCertificateChain() getPeerCertificates() getPeerHost() getPeerPort() getPeerPrincipal() getProtocol() getSessionContext() getValue(Ljava/lang/String;) getValueNames() invalidate() isValid() putValue(Ljava/lang/String;Ljava/lang/Object;) removeValue(Ljava/lang/String;)",
	},
	"javax/net/ssl/SSLSessionBindingEvent": {
		supers:  "java/util/EventObject",
		methods: "getName() getSession()",
	},
	"javax/net/ssl/SSLSessionBindingListener": {
		supers:  "java/util/EventListener",
		methods: "valueBound(Ljavax/net/ssl/SSLSessionBindingEvent;) valueUnbound(Ljavax/net/ssl/SSLSessionBindingEvent;)",
	},
	"javax/net/ssl/SSLSessionContext": {
		methods: "getIds() getSession([B) getSessionCacheSize() getSessionTimeout() setSessionCacheSize(I) setSessionTimeout(I)",
	},
	"javax/net/ssl/SSLSocket": {
		supers:  "java/net/Socket",
		methods: "addHandshakeCompletedListener(Ljavax/net/ssl/HandshakeCompletedListener;) getApplicationProtocol() getEnableSessionCreation() getEnabledCipherSuites() getEnabledProtocols() getHandshakeApplicationProtocol() getHandshakeApplicationProtocolSelector() getHandshakeSession() getNeedClientAuth() getSSLParameters() getSession() getSupportedCipherSuites() getSupportedProtocols() getUseClientMode() getWantClientAuth() removeHandshakeCompletedListener(Ljavax/net/ssl/HandshakeCompletedListener;) setEnableSessionCreation(Z) setEnabledCipherSuites([Ljava/lang/String;) setEnabledProtocols([Ljava/lang/String;) setHandshakeApplicationProtocolSelector(Ljava/util/function/BiFunction;) setNeedClientAuth(Z) setSSLParameters(Ljavax/net/ssl/SSLParameters;) setUseClientMode(Z) setWantClientAuth(Z) startHandshake()",
	},
	"javax/net/ssl/SSLSocketFactory": {
		supers:  "javax/net/SocketFactory",
		methods: "createSocket(Ljava/net/Socket;Ljava/io/InputStream;Z) createSocket(Ljava/net/Socket;Ljava/lang/String;IZ) getDefaultCipherSuites() getSupportedCipherSuites()",
	},
	"javax/net/ssl/TrustManager":        {},
	"javax/net/ssl/TrustManagerFactory": {},
	"javax/net/ssl/TrustManagerFactorySpi": {
		methods: "engineGetTrustManagers() engineInit(Ljava/security/KeyStore;) engineInit(Ljavax/net/ssl/ManagerFactoryParameters;)",
	},
	"javax/net/ssl/X509ExtendedKeyManager": {
		supers:  "javax/net/ssl/X509KeyManager",
		methods: "chooseEngineClientAlias([Ljava/lang/String;[Ljava/security/Principal;Ljavax/net/ssl/SSLEngine;) chooseEngineServerAlias(Ljava/lang/String;[Ljava/security/Principal;Ljavax/net/ssl/SSLEngine;)",
	},
	"javax/net/ssl/X509ExtendedTrustManager": {
		supers:  "javax/net/ssl/X509TrustManager",
		methods: "checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljava/net/Socket;) checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljavax/net/ssl/SSLEngine;) checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljava/net/Socket;) checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljavax/net/ssl/SSLEngine;)",
	},
	"javax/net/ssl/X509KeyManager": {
		supers:  "javax/net/ssl/KeyManager",
		methods: "chooseClientAlias([Ljava/lang/String;[Ljava/security/Principal;Ljava/net/Socket;) chooseServerAlias(Ljava/lang/String;[Ljava/security/Principal;Ljava/net/Socket;) getCertificateChain(Ljava/lang/String;) getClientAliases(Ljava/lang/String;[Ljava/security/Principal;) getPrivateKey(Ljava/lang/String;) getServerAliases(Ljava/lang/String;[Ljava/security/Principal;)",
	},
	"javax/net/ssl/X509TrustManager": {
		supers:  "javax/net/ssl/TrustManager",
		methods: "checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;) checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;) getAcceptedIssuers()",
	},
	"javax/security/auth/DestroyFailedException": {
		supers: "java/lang/Exception",
	},
	"javax/security/auth/Destroyable": {
		methods: "destroy() isDestroyed()",
	},
	"javax/security/auth/RefreshFailedException": {
		supers: "java/lang/Exception",
	},
	"javax/security/auth/Refreshable": {
		methods: "isCurrent() refresh()",
	},
	"javax/security/auth/SubjectDomainCombiner": {
		supers:  "java/security/DomainCombiner",
		methods: "combine([Ljava/security/ProtectionDomain;[Ljava/security/ProtectionDomain;) getSubject()",
	},
	"javax/security/auth/callback/Callback": {},
	"javax/security/auth/callback/CallbackHandler": {
		methods: "handle([Ljavax/security/auth/callback/Callback;)",
	},
	"javax/security/auth/callback/ChoiceCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "allowMultipleSelections() getChoices() getDefaultChoice() getPrompt() getSelectedIndexes() setSelectedIndex(I) setSelectedIndexes([I)",
	},
	"javax/security/auth/callback/ConfirmationCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "getDefaultOption() getMessageType() getOptionType() getOptions() getPrompt() getSelectedIndex() setSelectedIndex(I)",
	},
	"javax/security/auth/callback/LanguageCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "getLocale() setLocale(Ljava/util/Locale;)",
	},
	"javax/security/auth/callback/NameCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "getDefaultName() getName() getPrompt() setName(Ljava/lang/String;)",
	},
	"javax/security/auth/callback/PasswordCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "clearPassword() getPassword() getPrompt() isEchoOn() setPassword([C)",
	},
	"javax/security/auth/callback/TextInputCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "getDefaultText() getPrompt() getText() setText(Ljava/lang/String;)",
	},
	"javax/security/auth/callback/TextOutputCallback": {
		supers:  "javax/security/auth/callback/Callback java/io/Serializable",
		methods: "getMessage() getMessageType()",
	},
	"javax/security/auth/callback/UnsupportedCallbackException": {
		supers:  "java/lang/Exception",
		methods: "getCallback()",
	},
	"javax/security/auth/login/AccountException": {
		supers: "javax/security/auth/login/LoginException",
	},
	"javax/security/auth/login/AccountExpiredException": {
		supers: "javax/security/auth/login/AccountException",
	},
	"javax/security/auth/login/AccountLockedException": {
		supers: "javax/security/auth/login/AccountException",
	},
	"javax/security/auth/login/AccountNotFoundException": {
		supers: "javax/security/auth/login/AccountException",
	},
	"javax/security/auth/login/AppConfigurationEntry": {
		methods: "getControlFlag() getLoginModuleName() getOptions()",
	},
	"javax/security/auth/login/AppConfigurationEntry$LoginModuleControlFlag": {
		methods: "toString()",
	},
	"javax/security/auth/login/Configuration": {
		methods: "getAppConfigurationEntry(Ljava/lang/String;) getParameters() getProvider() getType() refresh()",
	},
	"javax/security/auth/login/Configuration$Parameters": {},
	"javax/security/auth/login/ConfigurationSpi": {
		methods: "engineGetAppConfigurationEntry(Ljava/lang/String;) engineRefresh()",
	},
	"javax/security/auth/login/CredentialException": {
		supers: "javax/security/auth/login/LoginException",
	},
	"javax/security/auth/login/CredentialExpiredException": {
		supers: "javax/security/auth/login/CredentialException",
	},
	"javax/security/auth/login/CredentialNotFoundException": {
		supers: "javax/security/auth/login/CredentialException",
	},
	"javax/security/auth/login/FailedLoginException": {
		supers: "javax/security/auth/login/LoginException",
	},
	"javax/security/auth/login/LoginContext": {
		methods: "getSubject() login() logout()",
	},
	"javax/security/auth/login/LoginException": {
		supers: "java/security/GeneralSecurityException",
	},
	"javax/security/auth/spi/LoginModule": {
		methods: "abort() commit() initialize(Ljavax/security/auth/Subject;Ljavax/security/auth/callback/CallbackHandler;Ljava/util/Map;Ljava/util/Map;) login() logout()",
	},
	"javax/security/cert/Certificate": {
		methods: "equals(Ljava/lang/Object;) getEncoded() getPublicKey() hashCode() toString() verify(Ljava/security/PublicKey;) verify(Ljava/security/PublicKey;Ljava/lang/String;)",
	},
	"javax/security/cert/CertificateEncodingException": {
		supers: "javax/security/cert/CertificateException",
	},
	"javax/security/cert/CertificateException": {
		supers: "java/lang/Exception",
	},
	"javax/security/cert/CertificateExpiredException": {
		supers: "javax/security/cert/CertificateException",
	},
	"javax/security/cert/CertificateNotYetValidException": {
		supers: "javax/security/cert/CertificateException",
	},
	"javax/security/cert/CertificateParsingException": {
		supers: "javax/security/cert/CertificateException",
	},
	"javax/security/cert/X509Certificate": {
		supers:  "javax/security/cert/Certificate",
		methods: "checkValidity() checkValidity(Ljava/util/Date;) getIssuerDN() getNotAfter() getNotBefore() getSerialNumber() getSigAlgName() getSigAlgOID() getSigAlgParams() getSubjectDN() getVersion()",
	},
}
