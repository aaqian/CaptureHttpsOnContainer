
/**
 * @author zxy
 * 参考了看雪论坛的珍惜大佬的代码XposedOkHttpCat，在此致谢！
 * 
 * 说明：
 * 本项目代码是作为安全容器中捕获开源框架中网络流量的部分，
 * 安全容器可参考VirtualApp，
 * 可在安全容器的启动插桩Activity处的代码逻辑中调用：
 *      Hook hook = new Hook();
 *      hook.HookOkClient(appClassLoader, context);   //入口，appClassLoader是插件应用的 ClassLoader
 */
public class Hook implements InvocationHandler {
    private String TAG                                      = "Hook_zxy";
    private ClassLoader classLoader                         = null;                        //目标应用的ClassLoader
    private Context context                                 = null;                        //目标应用的Context

    //存放 这个 app全部的 classloader
    private ArrayList<ClassLoader> AppAllCLassLoaderList    = new ArrayList<>();

    private FileOutputStream fos                            = null;                                                                                                 //将拦截到的日志写入到文件中
//    String filePath                                         = Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + "httpcontents.txt";    //vbooster_privacy_safe_space/httpcontents.txt
    String filePath = "/storage/emulated/0/httpcontents.txt";  //AlertService获取不到上一行的文件路径
    private ArrayList<String> mAllClassNameList             = new ArrayList<>();    //存放该插件APP中包含okhttp和okio的全部类名字的集合
    private ArrayList<Class> mClassList                     = new ArrayList<>();    //存放该插件APP中包含okhttp和okio的全部类的集合
    private Class<?> class_OkHttpClient                     = null;                 //OkHttpClient类
    private Class<?> class_OkHttpBuilder                    = null;                 //OkHttpBuilder类
    private Class<?> class_Interceptor                      = null;                 //okhttp3.Interceptor类
    private Class<?> class_HttpLoggingInterceptor           = null;                 //okhttp3.logging.HttpLoggingInterceptor类
    private Class<?> class_HttpLoggingInterceptorLogger     = null;                 //okhttp3.logging.HttpLoggingInterceptor$Logger类
    private Class<?> class_HttpLoggingInterceptorLevel      = null;                 //okhttp3.logging.HttpLoggingInterceptor$Level类

    private Object object_interceprot                       = null;

    private String dexPath                                  = null;                  //动态加载拦截器时，拦截器所在jar包位置, /data/data/包名/app_wxdex/logging.dex3.jar
    private String dexPath_okio                             = null;                  ///data/data/包名/app_wxdex_okio/okio.dex3.jar
    private String dexCache                                 = null;                  //优化路径，即dex文件在加载之前会优化成odex文件，/data/data/包名/app_wxdex
    private String dexCache_okio                            = null;                  ///data/data/包名/app_wxdex_okio
    private Object[] dexElements                            = null;                  //插件APP的ClassLoader中的Elements
    private Object[] dexElements_DexClassLoader             = null;                  //动态加载拦截器时，动态加载的DexClassLoader中的Elements

    /**
     * 入口
     *
     * @param loader  目标应用的ClassLoader
     * @param context 目标应用的Context
     */
    public void HookOkClient(ClassLoader loader, Context context) {
        if(fos == null){
            try {
                File file = new File(filePath);
                if(!file.exists()){
                    file.createNewFile();
                }
                fos = new FileOutputStream(filePath, true);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        Log.e("zxy","55555555the filepath is:::" + filePath);

        this.classLoader = loader;
        this.context = context;

        getAllClassName();
        initAllClass();

        getClientClass();
        getBuilderClass();
        getInterceptorClass();
        object_interceprot = getHttpLoggingInterceptorClass();

        if (object_interceprot == null) {
            Log.e(TAG, "HookOkClient::没有日志拦截器");
        }

        HookClientAndBuilderConstructor();
//        HookOutputStream();
//        HookCertificate();


    }

    public void HookCertificate(){
        try {

           Class<?> class_X509Certificate =  Class.forName("java.security.cert.X509Certificate", true, classLoader);
            Class array_class_X509Certificate = java.lang.reflect.Array.newInstance(class_X509Certificate, 1).getClass();
            EpicHelper.findAndHookMethod(
                    Class.forName("com.android.org.conscrypt.TrustManagerImpl", true, classLoader),
                    "checkTrusted",
                    array_class_X509Certificate,
                    String.class,
                    Class.forName("javax.net.ssl.SSLSession", true, classLoader),
                    Class.forName("javax.net.ssl.SSLParameters", true, classLoader),
                    boolean.class,
                    new XC_MethodHook() {
                        @Override
                        public void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            super.beforeHookedMethod(param);
                            StringBuilder TraceString = new StringBuilder();
                            TraceString.append("------------------hookhookhook222222--start------------------");
                            Throwable ex = new Throwable();
                            StackTraceElement[] stackTrace = ex.getStackTrace();
                            for (StackTraceElement stackTraceElement : stackTrace) {
//                                                        //FileUtils.SaveString(  );
                                                        TraceString.append("  类名#方法名: ")
                                                                .append(stackTraceElement.getClassName())
                                                                .append("#")
                                                                .append(stackTraceElement.getMethodName())
                                                                .append("   行号: ")
                                                                .append(stackTraceElement.getLineNumber())
                                                                .append("   文件名: ")
                                                                .append(stackTraceElement.getFileName())
                                                                .append("\n");
                            }
                            TraceString.append("------------------hookhookhook222222--end------------------");
                            Log.e(TAG, TraceString.toString());

                        }
                    });

        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();
        }

        try {

            EpicHelper.findAndHookMethod(
                    Class.forName("com.android.org.conscrypt.ConscryptFileDescriptorSocket", true, classLoader),
                    "verifyCertificateChain",
                    byte[][].class,
                    String.class,
                    new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                            return null;
                        }
                    });
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 获取该插件APP中包含okhttp和okio的类名，添加到变量 mAllClassNameList 中
     */
    public void getAllClassName() {
        mAllClassNameList.clear();
        if (classLoader == null) return;
        try {
            //1. 拿到PathClassLoader的父类BaseClassLoader，得到其属性pathList，该属性表示需要加载的dex列表，是DexPathList类型的
            Field field_pathList = classLoader.getClass().getSuperclass().getDeclaredField("pathList");
            if (field_pathList != null) {
                field_pathList.setAccessible(true);
                //2. 获取classLoader对象的DexPathList类型的值，即拿到BaseClassLoader.pathList。field.get(obj)的作用是获取obj对象的此field对象代表的字段的值。
                Object object_DexPathList = field_pathList.get(classLoader);
                //3. 拿到DexPathList.dexElements，是Element[]类型的。在dalvik下，每个dex加载成功后，会对应成一个DexFile对象，Element等同于一个dex
                Field field_dexElements = object_DexPathList.getClass().getDeclaredField("dexElements");
                if (field_dexElements != null) {
                    field_dexElements.setAccessible(true);
                    dexElements = (Object[]) field_dexElements.get(object_DexPathList);
                    for (Object dexElement : dexElements) {
                        Field field_dexFile = dexElement.getClass().getDeclaredField("dexFile");
                        if (field_dexFile != null) {
                            field_dexFile.setAccessible(true);
                            DexFile dexFile = (DexFile) field_dexFile.get(dexElement);
                            getDexFileClassName(dexFile);
                        } else {
                            Log.e(TAG, "initAllClassName::field_dexFile is NULL");
                        }
                    }
                } else {
                    Log.e(TAG, "initAllClassName::field_dexElements is NULL");
                }
            } else {
                Log.e(TAG, "initAllClassName::field_pathList is NULL");
            }
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    private void getDexFileClassName(DexFile dexFile) {
        if (dexFile == null) {
            return;
        }
        //获取df中的元素  这里包含了所有可执行的类名 该类名包含了包名+类名的方式
        Enumeration<String> enumeration = dexFile.entries();
        while (enumeration.hasMoreElements()) {//遍历
            String className = enumeration.nextElement();
            //添加过滤信息
            if (className.contains("okhttp") || className.contains("okio")
            ) {
                mAllClassNameList.add(className);
            }
        }
    }

    /**
     * 初始化 mAllClassNameList 中的类
     */
    public void initAllClass() {
        mClassList.clear();
        Log.e(TAG, "initAllClass::需要初始化的Class的个数为::" + mAllClassNameList.size());
        Class<?> mClass = null;
        for (int i = 0; i < mAllClassNameList.size(); i++) {
            mClass = getClass(mAllClassNameList.get(i));
            if (mClass != null) {
                mClassList.add(mClass);
            }
        }
        Log.e(TAG, "initAllClass::已经初始化的Class的个数为::" + mClassList.size());
    }

    public void getClientClass() {
        if (class_OkHttpClient == null) {
            try {
                class_OkHttpClient = Class.forName("okhttp3.OkHttpClient", true, classLoader);
            } catch (ClassNotFoundException e) {
                Log.e(TAG, "getClientClass::对方没有使用OkHttp 或者 OkHttp被混淆，开始尝试自动获取该类路径");
                if (mClassList.size() == 0) {
                    Log.e(TAG, "getClientClass::全部mClassList为0");
                    return;
                }
                Log.e(TAG, "getClientClass::开始在全部mClassList中查找OkHttpClient");
                for (Class mClient : mClassList) {
                    if (isClient(mClient)) {
                        class_OkHttpClient = mClient;
                        return;
                    }
                }
                Log.e(TAG, "getClientClass::没找到OkHttpClient");
            }
        }
    }

    /**
     * @param mClass
     * @return 根据类特征来判断是否为 OkHttpClient 类
     */
    public boolean isClient(Class mClass) {
        int typeCount = 0;
        int StaticCount = 0;
        //getDeclaredFields 是个 获取 全部的
        Field[] fields = mClass.getDeclaredFields();
        for (Field field : fields) {
            field.setAccessible(true);
            String type = field.getType().getName();
            //四个 集合 四个final 特征
            if (type.contains(List.class.getName()) && Modifier.isFinal(field.getModifiers())) {
                typeCount++;
            }
            if (type.contains(List.class.getName()) && Modifier.isFinal(field.getModifiers()) && Modifier.isStatic(field.getModifiers())) {
                StaticCount++;
            }
            if (StaticCount >= 2 && typeCount == 6 && mClass.getInterfaces().length >= 1) {
                CLogUtils.e("找到OkHttpClient  该类的名字是  " + mClass.getName());
                return true;
            }
        }
        return false;
    }

    public void getBuilderClass() {
        if (class_OkHttpBuilder == null) {
            try {
                class_OkHttpBuilder = Class.forName("okhttp3.OkHttpClient$Builder", true, classLoader);
            } catch (ClassNotFoundException e) {
                Log.e(TAG, "getBuilderClass::对方没有使用 Builder 或者 Builder 被混淆，开始尝试自动获取该类路径");
                if (mClassList.size() == 0) {
                    Log.e(TAG, "getBuilderClass::全部mClassList为0");
                    return;
                }
                Log.e(TAG, "getBuilderClass::开始在全部mClassList中查找 Builder");
                for (Class mBuilder : mClassList) {
                    if (isBuilder(mBuilder)) {
                        class_OkHttpBuilder = mBuilder;
                        return;
                    }
                }
                Log.e(TAG, "getBuilderClass::没找到 Builder");
            }
        }
    }

    private boolean isBuilder(@NonNull Class ccc) {
        try {
            int ListTypeCount = 0;
            int FinalTypeCount = 0;
            Field[] fields = ccc.getDeclaredFields();
            for (Field field : fields) {
                String type = field.getType().getName();
                //四个 集合
                if (type.contains(List.class.getName())) {
                    ListTypeCount++;
                }
                //2 个 为 final类型
                if (type.contains(List.class.getName()) && Modifier.isFinal(field.getModifiers())) {
                    FinalTypeCount++;
                }
            }
            //四个 List 两个 2 final  并且 包含父类名字
            if (ListTypeCount == 4 && FinalTypeCount == 2 && ccc.getName().contains(class_OkHttpClient.getName())) {
                Log.e(TAG, " isBuilder:::找到 Builder  " + ccc.getName());
                return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    public void getInterceptorClass() {
        if (class_Interceptor == null) {
            try {
                class_Interceptor = Class.forName("okhttp3.Interceptor", true, classLoader);
            } catch (ClassNotFoundException e) {
                Log.e(TAG, "ggetInterceptorClass::对方没有使用 Interceptor 或者 Interceptor 被混淆，开始尝试自动获取该类路径");
                if (mClassList.size() == 0) {
                    Log.e(TAG, "getInterceptorClass::全部mClassList为0");
                    return;
                }
                Log.e(TAG, "getInterceptorClass::开始在全部mClassList中查找 Interceptor");
                for (Class mInteceptor : mClassList) {
                    if (isInterceptorClass(mInteceptor)) {
                        class_Interceptor = mInteceptor;
                        return;
                    }
                }
                Log.e(TAG, "getInterceptorClass::没找到 Interceptor");
            }
        }
    }

    private boolean isInterceptorClass(Class mClass) {
        if (mClass == null) {
            return false;
        }
        try {
            Method[] declaredMethods = mClass.getDeclaredMethods();
            //一个方法 并且 方法参数 是 内部的接口
            if (declaredMethods.length == 1
                    && mClass.isInterface()
            ) {
                Method declaredMethod = declaredMethods[0];
                Class<?>[] parameterTypes = declaredMethod.getParameterTypes();

                return parameterTypes.length == 1 &&
                        parameterTypes[0].getName().contains(mClass.getName()) &&
                        declaredMethod.getExceptionTypes().length == 1 &&
                        declaredMethod.getExceptionTypes()[0].getName().equals(IOException.class.getName());

            }
        } catch (Throwable e) {
            CLogUtils.e("isInterceptorClass error " + e.toString());
        }
        return false;
    }


    /**
     * @return 初始化好的拦截器 HttpLoggingInterceptor
     */
    public synchronized Object getHttpLoggingInterceptorClass() {
        if (class_HttpLoggingInterceptor == null && class_HttpLoggingInterceptorLogger == null) {
            try {
                class_HttpLoggingInterceptor = Class.forName("okhttp3.logging.HttpLoggingInterceptor", true, classLoader);
                class_HttpLoggingInterceptorLogger = Class.forName("okhttp3.logging.HttpLoggingInterceptor$Logger", true, classLoader);
                if (class_HttpLoggingInterceptor != null && class_HttpLoggingInterceptorLogger != null) {
                    Log.e(TAG, "getHttpLoggingInterceptorClass::拿到了 App 本身的拦截器");
                    return InitLoggingInterceptor();
                }
            } catch (ClassNotFoundException e) {

                Log.e(TAG, "getHttpLoggingInterceptorClass::对方没有使用 HttpLoggingInterceptor 或者 HttpLoggingInterceptor 被混淆，开始尝试自动获取该类路径");

                /***************  1. 通过 mClassList 和 拦截器类的特征 来寻找拦截器 ************/
                if (mClassList.size() == 0) {
                    Log.e(TAG, "getHttpLoggingInterceptorClass::全部mClassList为0");
                    return null;
                }
                Log.e(TAG, "getHttpLoggingInterceptorClass::开始在全部mClassList中查找 Interceptor");
                //1. 开始找HttpLoggingInterceptor
                for (Class mInteceptor : mClassList) {
                    if (isHttpLoggingInterceptorClass(mInteceptor)) {
                        class_HttpLoggingInterceptor = mInteceptor;
                        //2. 开始找HttpLoggingInterceptor$Logger
                        for (Class mLogger : mClassList) {
                            if (isHttpLoggingInterceptorLoggerClass(mLogger)) {
                                class_HttpLoggingInterceptorLogger = mLogger;
                                //3. 开始找HttpLoggingInterceptor$Level
                                for (Class mLevel : mClassList) {
                                    if (isHttpLoggingInterceptorLevelClass(mLevel)) {
                                        class_HttpLoggingInterceptorLevel = mLevel;
                                        return InitLoggingInterceptor();
                                    }
                                }
                            }
                        }
                    }

                }
                Log.e(TAG, "getHttpLoggingInterceptorClass:: 111-没找到 Interceptor");


                /***************  2. 直接尝试动态加载 拦截器 ************/
                Object  obj = dexLoggingInterceptor();
                if(obj != null){
                    return obj;
                }
                Log.e(TAG, "getHttpLoggingInterceptorClass:: 222-没找到 Interceptor");


                /***************  3. 自己实现 拦截器 ************/
//                getHttpLoggingInterceptorImp();
                Log.e(TAG, "getHttpLoggingInterceptorClass:: 333-没找到 Interceptor");
            }
        } else {
            Log.e(TAG, "getHttpLoggingInterceptorClass::class_HttpLoggingInterceptor = null && class_HttpLoggingInterceptorLogger!=null");
        }
        return null;
    }

    public boolean isHttpLoggingInterceptorClass(Class mClass) {
        //Class本身是final类型 并且实现了拦截器接口，拦截器接口个数1
        try {
            if (Modifier.isFinal(mClass.getModifiers()) && mClass.getInterfaces().length == 1) {

                Field[] declaredFields = mClass.getDeclaredFields();
                for (Field field : declaredFields) {
                    int setCount = 0;
                    int charSetCount = 0;
                    //  private volatile Set<String> headersToRedact = Collections.emptySet();
                    if (field.getType().getName().equals(Set.class.getName())
                            && Modifier.isPrivate(field.getModifiers())
                            && Modifier.isVolatile(field.getModifiers())
                    ) {
                        setCount++;
                    }
                    //  private static final Charset UTF8 = Charset.forName("UTF-8");
                    if (field.getType().getName().equals(Charset.class.getName())
                            && Modifier.isPrivate(field.getModifiers())
                            && Modifier.isStatic(field.getModifiers())
                            && Modifier.isFinal(field.getModifiers())
                    ) {
                        charSetCount++;
                    }
                    if (setCount == 1 && charSetCount == 1) {
                        CLogUtils.e("发现HttpLoggingInterceptor名字是 " + mClass.getName());
                        return true;
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean isHttpLoggingInterceptorLoggerClass(Class mClass) {
        if (mClass.isInterface() && mClass.getName().contains(class_HttpLoggingInterceptor.getName() + "$")) {
            class_HttpLoggingInterceptorLogger = mClass;
            return true;
        }
        return false;
    }

    public boolean isHttpLoggingInterceptorLevelClass(Class mClass) {
        if (mClass.isEnum() && mClass.getName().contains(class_HttpLoggingInterceptor.getName() + "$")) {
            class_HttpLoggingInterceptorLogger = mClass;
            return true;
        }
        return false;
    }


    /**
     * @return 开始动态加载初始化拦截器
     */
    public Object dexLoggingInterceptor() {
        Log.e(TAG, "initLoggingInterceptor::开始动态加载初始化拦截器");
        if (dexPath == null) {
            dexPath = download();
        }
        if(dexPath_okio == null){
            dexPath_okio = download2();
        }
        DexClassLoader mDexClassLoader = new DexClassLoader(dexPath, dexCache, null, classLoader);
        DexClassLoader mDexClassLoader_okio = new DexClassLoader(dexPath_okio, dexCache_okio, null, classLoader);
        if (AddElements(mDexClassLoader)) {
            if(AddElements(mDexClassLoader_okio)){
                Log.e(TAG, "initLoggingInterceptor::dex合并成功");
                try {
                    class_HttpLoggingInterceptor = classLoader.loadClass("okhttp3.logging.HttpLoggingInterceptor");
                    class_HttpLoggingInterceptorLogger = classLoader.loadClass("okhttp3.logging.HttpLoggingInterceptor$Logger");
                    if (class_HttpLoggingInterceptor != null && class_HttpLoggingInterceptorLogger != null) {
                        Log.e(TAG, "initLoggingInterceptor::动态 加载 classloader 成功");
                        return InitLoggingInterceptor();
                    }
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    //合并dex
    public boolean AddElements(DexClassLoader mDexClassLoader) {
        dexElements_DexClassLoader = getDexElements_DexClassLoader(mDexClassLoader);
        if (dexElements_DexClassLoader == null) {
            Log.e(TAG, "AddElements::dexElements_DexClassLoader is NULL");
            return false;
        } else {
            Log.e(TAG, "AddElements::dexElements_DexClassLoader lenght is:::" + dexElements_DexClassLoader.length);
            //系统的 classloader 里面的 elements 数组
            if (dexElements == null) {
                Log.e(TAG, "AddElements::dexElements is NULL");
                return false;
            } else {
                Log.e(TAG, "AddElements::dexElements lenght is:::" + dexElements.length);
                //DexElements 合并
                //1.创建一个Element类型的数组combinded，数组长度为上述两个数组长度之和
                Object[] combinded = (Object[]) Array.newInstance(dexElements.getClass().getComponentType(), dexElements.length + dexElements_DexClassLoader.length);
                //2.将dexElements数组中的字节数据放到数组combinded中
                System.arraycopy(dexElements, 0, combinded, 0, dexElements.length);
                //3.将dexElements_DexClassLoader数组中的字节数据放到数组combinded中
                System.arraycopy(dexElements_DexClassLoader, 0, combinded, dexElements.length, dexElements_DexClassLoader.length);

                if ((dexElements.length + dexElements_DexClassLoader.length) != combinded.length) {
                    Log.e(TAG, "合并 elements 数组失败");
                    return false;
                } else {
                    Log.e(TAG, "合并 elements 数组成功，并重新加载");
                    return SetDexElements(combinded, combinded.length);
                }

            }
        }
    }

    public Object[] getDexElements_DexClassLoader(DexClassLoader mDexClassLoader) {
        try {
            Field pathListField = mDexClassLoader.getClass().getSuperclass().getDeclaredField("pathList");
            if (pathListField != null) {
                pathListField.setAccessible(true);
                Object dexPathList = pathListField.get(mDexClassLoader);
                Field dexElementsField = dexPathList.getClass().getDeclaredField("dexElements");
                if (dexElementsField != null) {
                    dexElementsField.setAccessible(true);
                    Object[] dexElements = (Object[]) dexElementsField.get(dexPathList);
                    if (dexElements != null) {
                        return dexElements;
                    } else {
                        CLogUtils.e("AddElements  获取 dexElements == null");
                        return null;
                    }
                    //ArrayUtils.addAll(first, second);
                } else {
                    CLogUtils.e("AddElements  获取 dexElements == null");
                }
            }
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean SetDexElements(Object[] dexElementsResult, int count) {
        //1. 拿到PathClassLoader的父类BaseClassLoader，得到其属性pathList，该属性表示需要加载的dex列表，是DexPathList类型的
        Field field_pathList = null;
        try {
            field_pathList = classLoader.getClass().getSuperclass().getDeclaredField("pathList");
            if (field_pathList != null) {
                field_pathList.setAccessible(true);
                //2. 获取classLoader对象的DexPathList类型的值，即拿到BaseClassLoader.pathList。field.get(obj)的作用是获取obj对象的此field对象代表的字段的值。
                Object object_DexPathList = field_pathList.get(classLoader);
                //3. 拿到DexPathList.dexElements，是Element[]类型的。在dalvik下，每个dex加载成功后，会对应成一个DexFile对象，Element等同于一个dex
                Field field_dexElements = object_DexPathList.getClass().getDeclaredField("dexElements");
                if (field_dexElements != null) {
                    field_dexElements.setAccessible(true);
                    //先重新设置一次
                    field_dexElements.set(object_DexPathList, dexElementsResult);
                    //重新get
                    dexElements = (Object[]) field_dexElements.get(object_DexPathList);
                    if (dexElements.length == count && Arrays.hashCode(dexElements) == Arrays.hashCode(dexElementsResult)) {
                        return true;
                    } else {
                        Log.e(TAG, "SetDexElements :: 合成 长度 为::" + dexElements.length + " ::  传入 数组 长度 为 ::" + count);
                        Log.e(TAG, "SetDexElements :: dexElements hashCode " + Arrays.hashCode(dexElements) + "  " + Arrays.hashCode(dexElementsResult));
                        return false;
                    }
                } else {
                    Log.e(TAG, "SetDexElements :: field_dexElements  is NULL");
                }
            } else {
                Log.e(TAG, "SetDexElements :: field_pathList  is NULL");
            }
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return false;
    }


    /**
     * 初始化LoggingInterceptor
     */
    public Object InitLoggingInterceptor() {
        Object logger = Proxy.newProxyInstance(classLoader, new Class[]{class_HttpLoggingInterceptorLogger}, Hook.this);
        try {
            Object loggingInterceptor = class_HttpLoggingInterceptor.getConstructor(class_HttpLoggingInterceptorLogger).newInstance(logger);
            final Object level = classLoader.loadClass("okhttp3.logging.HttpLoggingInterceptor$Level").getEnumConstants()[3];
            // public HttpLoggingInterceptor setLevel(Level level)
            Method setLevelMethod = class_HttpLoggingInterceptor.getMethod("setLevel", level.getClass());
            Log.e(TAG, "InitLoggingInterceptor:::拦截器初始化成功");
            return setLevelMethod.invoke(loggingInterceptor, level);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


//    /**
//     * @return 自己实现拦截器
//     */
//    public Object getHttpLoggingInterceptorImp(){
//
//    }


    /**
     * @return /data/data/包名/app_wxdex/logging.dex3.jar  将assets目录下的wechat.jar的内容写入到 logging.dex3.jar 中
     */
    public String download() {
        File wechat = VirtualCore.get().getContext().getDir("wxdex", Context.MODE_PRIVATE);    //创建文件夹 /data/data/包名/app_wxdex 的文件夹
        File dex = new File(wechat, "logging.dex3.jar");   //文件  /data/data/包名/app_wxdex/logging.dex3.jar
        if (dex.exists()) dex.delete();
        if (!dex.exists()) {
            try {
                AssetManager assetManager = VirtualCore.get().getContext().getAssets();
                InputStream is = null;
                FileOutputStream fos = new FileOutputStream(dex);

                is = assetManager.open("logging.jar");
                byte[] bytes = new byte[is.available()];
                while ((is.read(bytes)) != -1) {
                    fos.write(bytes);
                }

//                is = assetManager.open("okio.jar");
//                byte[] bytes2 = new byte[is.available()];
//                while ((is.read(bytes2)) != -1) {
//                    fos.write(bytes2);
//                }

                is.close();
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return dex.getAbsolutePath();
    }

    /**
     * @return /data/data/包名/app_wxdex/okio.dex3.jar  将assets目录下的okio.jar的内容写入到 okio.dex3.jar 中
     */
    public String download2() {
        File wechat = VirtualCore.get().getContext().getDir("wxdex_okio", Context.MODE_PRIVATE);    //创建文件夹 /data/data/包名/app_wxdex_okio 的文件夹
        File dex = new File(wechat, "okio.dex3.jar");   //文件  /data/data/包名/app_wxdex_okio/okio.dex3.jar
        if (dex.exists()) dex.delete();
        if (!dex.exists()) {
            try {
                AssetManager assetManager = VirtualCore.get().getContext().getAssets();
                InputStream is = null;
                FileOutputStream fos = new FileOutputStream(dex);

                is = assetManager.open("okio.jar");
                byte[] bytes = new byte[is.available()];
                while ((is.read(bytes)) != -1) {
                    fos.write(bytes);
                }
                is.close();
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return dex.getAbsolutePath();
    }

    /**
     * @return 在该app中okhttp是否被混淆
     */
    public boolean isConfusion() {
        boolean noConfusion = class_OkHttpClient.getName().equals("okhttp3.OkHttpClient")
                && class_OkHttpBuilder.getName().equals("okhttp3.OkHttpClient$Builder")
                //拦截器里面常用的类不为NULL，才能保证插件正常加载
                && getClass("okio.Buffer") != null
                && getClass("okio.BufferedSource") != null
                && getClass("okio.GzipSource") != null
                && getClass("okhttp3.Request") != null
                && getClass("okhttp3.Response") != null
                && getClass("okio.Okio") != null
                && getClass("okio.Base64") != null;
        return !noConfusion;
    }

    /**
     * 遍历当前进程的Classloader 尝试进行获取指定类
     *
     * @param className
     * @return
     */
    private Class getClass(String className) {
        Class<?> aClass = null;
        try {
            try {
                aClass = Class.forName(className);
            } catch (ClassNotFoundException classNotFoundE) {

                try {
                    aClass = Class.forName(className, false, classLoader);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
                if (aClass != null) {
                    return aClass;
                }
                try {
                    for (ClassLoader classLoader : AppAllCLassLoaderList) {
                        try {
                            aClass = Class.forName(className, false, classLoader);
                        } catch (Throwable e) {
                            continue;
                        }
                        if (aClass != null) {
                            return aClass;
                        }
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                }
            }

            return aClass;
        } catch (Throwable e) {

        }
        return null;
    }

    /**
     * Hook Client 和 Builder的构造
     */
    public void HookClientAndBuilderConstructor() {
        if (class_OkHttpClient != null && class_OkHttpBuilder != null) {
            //新建OkHttpClient有以下三种方式，
            //        client = new OkHttpClient.Builder().build();
            //        client = new OkHttpClient();
            //         client = new OkHttpClient().newBuilder().build();
            //这三种方式最终都会调用，OkHttpClient(OkHttpBuilder)
            EpicHelper.findAndHookConstructor(
                    class_OkHttpClient,
                    class_OkHttpBuilder,
                    new XC_MethodHook() {
                        @Override
                        public void afterHookedMethod(MethodHookParam param) throws Throwable {
                            super.afterHookedMethod(param);
                        }

                        @Override
                        public void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            super.beforeHookedMethod(param);
                            Log.e(TAG, "HookClientAndBuilderConstructor::Hook 到 构造函数  OkHttpClient :: 开始添加拦截器");
                            AddInterceptors(param);
                        }
                    });
        } else {
            Log.e(TAG, "HookClientAndBuilderConstructor:: class_OkHttpClient==NULL || class_OkHttpBuilder==NULL");
        }
    }

    public synchronized void AddInterceptors(XC_MethodHook.MethodHookParam param) {
        if (class_Interceptor == null) {
            Log.e(TAG, "AddInterceptors:: class_Interceptor==NULL");
            return;
        }
        if (class_HttpLoggingInterceptor != null) {
            Log.e("zxy", "AddInterceptors:: class_HttpLoggingInterceptor:: " + class_HttpLoggingInterceptor.getName());
            if (AddInterceptorForList(param, object_interceprot)) {
                Log.e(TAG, "AddInterceptors:::添加拦截器完毕");
            }
        }
    }

    /**
     * @param param                  OkHttpBuilder。因为OkHttpClient(OkHttpBuilder)参数为OkHttpBuilder
     * @param httpLoggingInterceptor
     * @return
     */
    public boolean AddInterceptorForList(XC_MethodHook.MethodHookParam param, Object httpLoggingInterceptor) {
        try {
            Object object;
            if (param.args == null || param.args.length == 0) {
                object = param.thisObject;
                Log.e(TAG, "AddInterceptorForList:::object = param.thisObject");
            } else {
                object = param.args[0];
                Log.e(TAG, "AddInterceptorForList:::object = param.args[0] and param.args length is::" + param.args.length);
            }
            for (Field field : object.getClass().getDeclaredFields()) {
                if (field.getType().getName().equals(List.class.getName())) {
                    Type genericType = field.getGenericType();
                    if (genericType != null) {
                        ParameterizedType pt = (ParameterizedType) genericType;
                        // 得到泛型里的class类型对象
                        Class<?> actualTypeArgument = (Class<?>) pt.getActualTypeArguments()[0];
                        if (actualTypeArgument.getName().equals(class_Interceptor.getName())) {
                            field.setAccessible(true);
                            List list;
                            if (param.args.length == 0) {
                                list = (List) field.get(param.thisObject);
                            } else {
                                list = (List) field.get(param.args[0]);
                            }
                            list.add(httpLoggingInterceptor);
                            Log.e(TAG, "添加拦截器成功");
                            return true;
                        }
                    }
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void HookOutputStream(){
        //不能hook抽象类，而是要hook具体的实现类
        //write方法，最终会走到socketWrite方法
        try {
            EpicHelper.findAndHookMethod(
                    Class.forName("java.net.SocketOutputStream", true, classLoader),
                    "socketWrite",
                    byte[].class,
                    int.class,
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        public void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            super.beforeHookedMethod(param);
                            StringBuilder TraceString = new StringBuilder();
                            TraceString.append("------------------SocketOutputStream--start------------------");
                            TraceString.append(new String((byte[]) param.args[0], StandardCharsets.UTF_8));
                            TraceString.append("------------------SocketOutputStream--end------------------");
//                            WriteStringToFile(TraceString.toString());
                            WriteStringToFile(TraceString.toString());
                            Log.e(TAG, TraceString.toString());
                        }
                    });
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        try {
            EpicHelper.findAndHookMethod(Class.forName("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream", true, classLoader)
                    ,"write"
                    ,byte[].class
                    ,int.class
                    ,int.class
                    ,new XC_MethodHook(){
                        @Override
                        public void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            StringBuilder TraceString = new StringBuilder();
                            TraceString.append("------------------SSLOutputStream--start------------------");
                            TraceString.append(new String((byte[]) param.args[0], StandardCharsets.UTF_8));
                            TraceString.append("------------------SSLOutputStream--end------------------");
    //                        WriteStringToFile(TraceString.toString());
                            Log.e(TAG, TraceString.toString());
                        }
                    });
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }


    }

    public void WriteStringToFile(String content) {
        try {
            fos.write(content.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //动态代理
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getName().equals("log")) {
            //1. 将结果写入到文件中
            StringBuilder TraceString = new StringBuilder();
            TraceString.append(args[0]);
            WriteStringToFile(TraceString.toString() + "\n");

            //2. 打印到Logcat上
//            Log.e("zxy", "logger.log:::" + args[0]);
        }
        return null;
    }
}
