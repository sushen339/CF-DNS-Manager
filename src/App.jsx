import React, { useState, useEffect, useRef } from 'react';
import { Globe, Server, User, Shield, Key, LogOut, Plus, Trash2, Edit2, ExternalLink, RefreshCw, Zap, Languages, CheckCircle, AlertCircle, X, Search, ChevronDown, Upload, Download, Copy } from 'lucide-react';

// Translations
const translations = {
    zh: {
        title: 'DNS 管理面板',
        subtitle: '安全地管理您的 Cloudflare 域名',
        serverMode: '托管模式',
        clientMode: '本地模式',
        passwordLabel: '管理员密码',
        passwordPlaceholder: '输入应用密码...',
        tokenLabel: 'Cloudflare API 令牌',
        tokenPlaceholder: '粘贴您的 API 令牌...',
        tokenHint: '令牌通过 Header 传输，后端仅作透明代理。',
        serverHint: '后端基于 Pages 环境变量运行，支持多用户登录。',
        loginBtn: '进入仪表盘',
        loginFailed: '登录失败',
        errorOccurred: '发生错误',
        yourDomains: '您的域名',
        domainSubtitle: '选择一个域名以管理其 DNS 和 SaaS 设置',
        refresh: '刷新',
        id: 'ID',
        manage: '管理',
        back: '返回列表',
        dnsRecords: 'DNS 记录',
        saasHostnames: '自定义主机名',
        addRecord: '添加记录',
        type: '类型',
        name: '名称',
        content: '内容',
        proxied: '代理',
        actions: '操作',
        hostname: '主机名',
        status: '状态',
        sslStatus: 'SSL 状态',
        confirmDelete: '您确定要删除此记录吗？',
        logout: '退出登录',
        managed: '托管',
        clientOnly: '本地',
        cancel: '取消',
        save: '保存',
        addModalTitle: '添加新 DNS 记录',
        confirmTitle: '确认操作',
        confirmDeleteText: '此操作不可撤销，您确定要继续吗？',
        yes: '确定',
        no: '否',
        statusActive: '激活',
        statusPending: '待处理',
        statusInitializing: '初始化',
        statusMoved: '已移除',
        statusDeactivated: '已停用',
        rememberMe: '记住登录状态',
        rememberToken: '记住 API 令牌',
        searchPlaceholder: '搜索记录...',
        editRecord: '编辑记录',
        addSaaS: '添加自定义主机名',
        confirmDeleteSaaS: '确定要删除此自定义主机名吗？',
        proxiedHint: '开启后流量将经过 Cloudflare 加速与防护',
        hostnamePlaceholder: '例如: app.example.com',
        fallbackOrigin: '回退源',
        fallbackOriginPlaceholder: '例如 origin.example.com',
        updateFallback: '更新',
        fallbackStatus: '回退源状态',
        sslMethod: 'SSL 验证方法',
        sslType: '证书类型',
        sslMethodTxt: 'TXT 记录',
        sslMethodHttp: 'HTTP 验证',
        sslMethodCname: 'CNAME 验证',
        sslMethodEmail: '邮件验证',
        httpWarning: '安全警告：检测到不安全的 HTTP 连接。为保护您的令牌，禁止在非 HTTPS 环境下发送敏感信息（Localhost 除外）。',
        recommended: '推荐',
        copied: '已复制到剪贴板',
        updateSuccess: '更新成功',
        addSuccess: '添加成功',
        deleteSuccess: '删除成功',
        importSuccess: '导入成功',
        exportSuccess: '导出成功',
        batchDelete: '批量删除',
        confirmBatchDelete: '您确定要删除选中的 {count} 条记录吗？',
        comment: '备注',
        priority: '优先级',
        weight: '权重',
        port: '端口',
        service: '服务',
        protocol: '协议',
        tag: '标签',
        flags: '标记',
        import: '导入',
        export: '导出',
        uploadFile: '上传配置文件',
        order: '顺序',
        preference: '优先级',
        regex: '正则表达式',
        replacement: '替换值',
        algorithm: '算法',
        fingerprint: '指纹',
        keyTag: '密钥标签',
        digestType: '摘要类型',
        digest: '摘要内容',
        usage: '用法',
        selector: '选择器',
        matchingType: '匹配类型',
        certificate: '证书',
        target: '目标',
        value: '内容值',
        ttl: 'TTL',
        ttlAuto: '自动',
        ttl1min: '1 分钟',
        ttl2min: '2 分钟',
        ttl5min: '5 分钟',
        ttl10min: '10 分钟',
        ttl15min: '15 分钟',
        ttl30min: '30 分钟',
        ttl1h: '1 小时',
        ttl2h: '2 小时',
        ttl5h: '5 小时',
        ttl12h: '12 小时',
        ttl1d: '1 天',
        ownership: '所有权验证',
        sslValidation: 'SSL 验证',
        verifyMethod: '验证方法',
        verifyType: '验证类型',
        verifyName: '验证名称',
        verifyValue: '验证内容',
        certificateStatus: '证书状态',
        hostnameStatus: '主机名状态',
        verificationRecords: '验证记录',
        noVerificationNeeded: '不需要验证',
        editSaaS: '编辑自定义主机名',
        minTlsVersion: '最低 TLS 版本',
        certType: '证书类型',
        certCloudflare: '由 Cloudflare 提供',
        certCustom: '自定义证书',
        originServer: '源服务器',
        defaultOrigin: '默认源服务器',
        customOrigin: '自定义源服务器',
        originPlaceholder: '例如: origin.example.com',
        tlsDefault: 'TLS 1.0 (默认)',
        active: '有效',
        pending_validation: '待验证',
        pending_deployment: '部署中',
        pending: '待处理',
        switchZone: '切换域名',
        noZonesFound: '未找到域名',
        fallbackError: '无法编辑此记录，因为它已被配置为 SSL for SaaS 的回退源。',
        invalidPassword: '无效的密码',
        serverNotConfigured: '服务器尚未配置密码登录',
        switchAccount: '切换账户',
        not_set: '未设置',
        invalidToken: '无效的 API 令牌',
        tokenRequired: '请输入 API 令牌',
        verifyFailed: '令牌校验失败',
    },
    en: {
        title: 'DNS Manager',
        subtitle: 'Manage your Cloudflare domains securely',
        serverMode: 'Server Mode',
        clientMode: 'Client Mode',
        passwordLabel: 'Administrator Password',
        passwordPlaceholder: 'Enter app password...',
        tokenLabel: 'Cloudflare API Token',
        tokenPlaceholder: 'Paste your API token...',
        tokenHint: 'Tokens are sent via header as a transparent proxy.',
        serverHint: 'The backend runs on Pages environment variables.',
        loginBtn: 'Access Dashboard',
        loginFailed: 'Login failed',
        errorOccurred: 'An error occurred',
        yourDomains: 'Your Domains',
        domainSubtitle: 'Select a zone to manage its DNS and SaaS settings',
        refresh: 'Refresh',
        id: 'ID',
        manage: 'Manage',
        back: 'Back to Zones',
        dnsRecords: 'DNS Records',
        saasHostnames: 'Custom Hostnames',
        addRecord: 'Add Record',
        type: 'Type',
        name: 'Name',
        content: 'Content',
        proxied: 'Proxied',
        actions: 'Actions',
        hostname: 'Hostname',
        status: 'Status',
        sslStatus: 'SSL Status',
        confirmDelete: 'Are you sure you want to delete this record?',
        logout: 'Logout',
        managed: 'Managed',
        clientOnly: 'Client-Only',
        cancel: 'Cancel',
        save: 'Save',
        addModalTitle: 'Add New DNS Record',
        confirmTitle: 'Confirm Action',
        confirmDeleteText: 'This action cannot be undone, are you sure you want to continue?',
        yes: 'Confirm',
        no: 'No',
        statusActive: 'Active',
        statusPending: 'Pending',
        statusInitializing: 'Initializing',
        statusMoved: 'Moved',
        statusDeactivated: 'Deactivated',
        rememberMe: 'Stay logged in',
        rememberToken: 'Remember API Token',
        searchPlaceholder: 'Search records...',
        editRecord: 'Edit Record',
        addSaaS: 'Add Custom Hostname',
        confirmDeleteSaaS: 'Are you sure you want to delete this custom hostname?',
        proxiedHint: 'Traffic will be accelerated and protected by Cloudflare',
        hostnamePlaceholder: 'Enter full hostname (e.g. shop.example.com)',
        fallbackOrigin: 'Fallback Origin',
        fallbackOriginPlaceholder: 'e.g. origin.example.com',
        updateFallback: 'Update Fallback Origin',
        fallbackStatus: 'Fallback Status',
        sslMethod: 'SSL Method',
        sslType: 'SSL Type',
        sslMethodTxt: 'TXT Record',
        sslMethodHttp: 'HTTP Validation',
        sslMethodCname: 'CNAME Validation',
        sslMethodEmail: 'Email Validation',
        httpWarning: 'Security Warning: Insecure HTTP connection detected. To protect your token, sending sensitive information over non-HTTPS is prohibited (except for Localhost).',
        recommended: 'Recommended',
        copied: 'Copied to clipboard',
        updateSuccess: 'Update Successful',
        addSuccess: 'Added Successfully',
        deleteSuccess: 'Deleted Successfully',
        importSuccess: 'Import Successful',
        exportSuccess: 'Export Successful',
        batchDelete: 'Batch Delete',
        confirmBatchDelete: 'Are you sure you want to delete {count} selected records?',
        comment: 'Comment',
        priority: 'Priority',
        weight: 'Weight',
        port: 'Port',
        service: 'Service',
        protocol: 'Protocol',
        tag: 'Tag',
        flags: 'Flags',
        import: 'Import',
        export: 'Export',
        uploadFile: 'Upload Config File',
        order: 'Order',
        preference: 'Preference',
        regex: 'Regex',
        replacement: 'Replacement',
        algorithm: 'Algorithm',
        fingerprint: 'Fingerprint',
        keyTag: 'Key Tag',
        digestType: 'Digest Type',
        digest: 'Digest',
        usage: 'Usage',
        selector: 'Selector',
        matchingType: 'Matching Type',
        certificate: 'Certificate',
        target: 'Target',
        value: 'Value',
        ttl: 'TTL',
        ttlAuto: 'Automatic',
        ttl1min: '1 min',
        ttl2min: '2 min',
        ttl5min: '5 min',
        ttl10min: '10 min',
        ttl15min: '15 min',
        ttl30min: '30 min',
        ttl1h: '1 hour',
        ttl2h: '2 hours',
        ttl5h: '5 hours',
        ttl12h: '12 hours',
        ttl1d: '1 day',
        ownership: 'Ownership Verification',
        sslValidation: 'SSL Validation',
        verifyMethod: 'Verification Method',
        verifyType: 'Verification Type',
        verifyName: 'Verification Name',
        verifyValue: 'Verification Value',
        certificateStatus: 'Certificate Status',
        hostnameStatus: 'Hostname Status',
        verificationRecords: 'Verification Records',
        noVerificationNeeded: 'No verification needed',
        editSaaS: 'Edit Custom Hostname',
        minTlsVersion: 'Minimum TLS Version',
        certType: 'Certificate Type',
        certCloudflare: 'Cloudflare Provided',
        certCustom: 'Custom Certificate',
        originServer: 'Origin Server',
        defaultOrigin: 'Default Origin',
        customOrigin: 'Custom Origin',
        originPlaceholder: 'e.g. origin.example.com',
        tlsDefault: 'TLS 1.0 (Default)',
        active: 'Active',
        pending_validation: 'Pending Validation',
        pending_deployment: 'Pending Deployment',
        pending: 'Pending',
        switchZone: 'Switch Domain',
        noZonesFound: 'No domains found. Please check your token or add a domain in Cloudflare.',
        fallbackError: 'Unable to edit this record as it is configured as a fallback origin for SSL for SaaS.',
        invalidPassword: 'Invalid password',
        serverNotConfigured: 'Server is not configured for password login',
        switchAccount: 'Switch Account',
        not_set: 'Not Set',
        invalidToken: 'Invalid API Token',
        tokenRequired: 'API Token is required',
        verifyFailed: 'Token verification failed',
    }
};

// Language Context / Helper
const useTranslate = () => {
    const [lang, setLang] = useState(localStorage.getItem('lang') || 'zh');

    const t = (key) => translations[lang][key] || key;

    const changeLang = (l) => {
        setLang(l);
        localStorage.setItem('lang', l);
    };

    const toggleLang = () => {
        const nextLang = lang === 'zh' ? 'en' : 'zh';
        changeLang(nextLang);
    };

    return { t, lang, changeLang, toggleLang };
};

const getAuthHeaders = (auth, withType = false) => {
    if (!auth) return {};
    const h = auth.mode === 'server'
        ? {
            'Authorization': `Bearer ${auth.token}`,
            'X-Managed-Account-Index': String(auth.currentAccountIndex || 0)
        }
        : { 'X-Cloudflare-Token': auth.token };
    if (withType) h['Content-Type'] = 'application/json';
    return h;
};

// Custom Select Component
const CustomSelect = ({ value, options, onChange, placeholder = "Select..." }) => {
    const [isOpen, setIsOpen] = useState(false);
    const wrapperRef = useRef(null);

    useEffect(() => {
        function handleClickOutside(event) {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [wrapperRef]);

    const handleSelect = (val) => {
        onChange({ target: { value: val } });
        setIsOpen(false);
    };

    const selectedOption = options.find(o => String(o.value) === String(value));
    const currentLabel = selectedOption ? selectedOption.label : value;

    return (
        <div ref={wrapperRef} style={{ position: 'relative', width: '100%' }}>
            <div
                onClick={() => setIsOpen(!isOpen)}
                style={{
                    padding: '0.625rem 0.875rem',
                    background: 'white',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    fontSize: '0.875rem',
                    minHeight: '42px',
                    borderColor: isOpen ? 'var(--primary)' : 'var(--border)',
                    boxShadow: isOpen ? '0 0 0 3px rgba(243, 128, 32, 0.1)' : 'none',
                    transition: 'all 0.2s'
                }}
            >
                <span style={{ color: selectedOption ? 'var(--text)' : 'var(--text-muted)' }}>
                    {currentLabel || placeholder}
                </span>
                <ChevronDown size={16} color="var(--text-muted)" style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }} />
            </div>
            {isOpen && (
                <div style={{
                    position: 'absolute',
                    top: '100%',
                    left: 0,
                    right: 0,
                    background: 'white',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    marginTop: '4px',
                    maxHeight: '220px',
                    overflowY: 'auto',
                    zIndex: 50,
                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
                }}>
                    {options.map(opt => (
                        <div
                            key={opt.value}
                            onClick={() => handleSelect(opt.value)}
                            style={{
                                padding: '0.625rem 0.875rem',
                                cursor: 'pointer',
                                fontSize: '0.875rem',
                                background: String(opt.value) === String(value) ? '#fff7ed' : 'transparent',
                                color: String(opt.value) === String(value) ? 'var(--primary)' : 'var(--text)',
                                fontWeight: String(opt.value) === String(value) ? '500' : '400',
                                borderBottom: '1px solid #f7fafc'
                            }}
                            onMouseEnter={(e) => { if (String(opt.value) !== String(value)) e.target.style.background = '#f9fafb'; }}
                            onMouseLeave={(e) => { if (String(opt.value) !== String(value)) e.target.style.background = 'transparent'; }}
                        >
                            {opt.label}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

// Components
const Login = ({ onLogin, t, lang, onLangChange }) => {
    const [password, setPassword] = useState('');
    const [token, setToken] = useState('');
    const [isServerMode, setIsServerMode] = useState(true);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const [remember, setRemember] = useState(false);

    // 辅助函数：生成 SHA-256 哈希
    const hashPassword = async (pwd) => {
        const msgUint8 = new TextEncoder().encode(pwd);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const handleLogin = async (e) => {
        e.preventDefault();

        // Security Check: Block HTTP except for localhost
        const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
        if (window.location.protocol === 'http:' && !isLocalhost) {
            setError(t('httpWarning'));
            setLoading(false);
            return;
        }

        setLoading(true);
        setError('');

        try {
            if (isServerMode) {
                const hashedPassword = await hashPassword(password);
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: hashedPassword })
                });
                const data = await res.json();
                if (res.ok) {
                    onLogin({
                        mode: 'server',
                        token: data.token,
                        remember,
                        accounts: data.accounts || [],
                        currentAccountIndex: 0
                    });
                } else {
                    let errMsg = data.error || t('loginFailed');
                    if (errMsg.includes('Invalid password')) errMsg = t('invalidPassword');
                    if (errMsg.includes('Server is not configured')) errMsg = t('serverNotConfigured');
                    setError(errMsg);
                }
            } else {
                const res = await fetch('/api/verify-token', {
                    headers: { 'X-Cloudflare-Token': token }
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    onLogin({ mode: 'client', token: token, remember });
                } else {
                    let errMsg = data.message || t('loginFailed');
                    if (errMsg === 'Invalid token') errMsg = t('invalidToken');
                    if (errMsg === 'No token provided') errMsg = t('tokenRequired');
                    if (errMsg === 'Failed to verify token') errMsg = t('verifyFailed');
                    setError(errMsg);
                }
            }
        } catch (err) {
            setError(t('errorOccurred'));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="container" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', padding: '1rem' }}>
            <div className="glass-card login-card fade-in">
                <div style={{ position: 'absolute', top: '1rem', right: '1rem', zIndex: 10 }}>
                    <button
                        onClick={(e) => {
                            e.preventDefault();
                            onLangChange(lang === 'zh' ? 'en' : 'zh');
                        }}
                        style={{ border: 'none', background: 'transparent', padding: '8px', cursor: 'pointer', display: 'flex', color: 'var(--text-muted)', borderRadius: '8px', transition: 'background 0.2s' }}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,0,0,0.05)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                        title={lang === 'zh' ? 'English' : '中文'}
                    >
                        <Languages size={20} />
                    </button>
                </div>

                <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
                    <div style={{ display: 'inline-flex', padding: '0.75rem', background: 'rgba(243, 128, 32, 0.1)', borderRadius: '12px', marginBottom: '1rem' }}>
                        <Zap size={32} color="var(--primary)" />
                    </div>
                    <h1 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>{t('title')}</h1>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{t('subtitle')}</p>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', padding: '4px', background: '#f3f4f6', borderRadius: '8px' }}>
                    <button
                        className={`btn ${isServerMode ? 'btn-primary' : 'btn-outline'}`}
                        style={{ flex: 1, padding: '0.4rem', border: 'none' }}
                        onClick={() => setIsServerMode(true)}
                    >
                        {t('serverMode')}
                    </button>
                    <button
                        className={`btn ${!isServerMode ? 'btn-primary' : 'btn-outline'}`}
                        style={{ flex: 1, padding: '0.4rem', border: 'none' }}
                        onClick={() => setIsServerMode(false)}
                    >
                        {t('clientMode')}
                    </button>
                </div>

                <form onSubmit={handleLogin}>
                    {isServerMode ? (
                        <div className="input-group">
                            <label>{t('passwordLabel')}</label>
                            <div style={{ position: 'relative' }}>
                                <Key size={16} style={{ position: 'absolute', left: '12px', top: '12px', color: 'var(--text-muted)' }} />
                                <input
                                    type="password"
                                    placeholder={t('passwordPlaceholder')}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    style={{ paddingLeft: '38px' }}
                                    required
                                />
                            </div>
                            <p style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-muted)' }}>
                                {t('serverHint')}
                            </p>
                        </div>
                    ) : (
                        <div className="input-group">
                            <label>{t('tokenLabel')}</label>
                            <div style={{ position: 'relative' }}>
                                <Shield size={16} style={{ position: 'absolute', left: '12px', top: '12px', color: 'var(--text-muted)' }} />
                                <input
                                    type="password"
                                    placeholder={t('tokenPlaceholder')}
                                    value={token}
                                    onChange={(e) => setToken(e.target.value)}
                                    style={{ paddingLeft: '38px' }}
                                    required
                                />
                            </div>
                            <p style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-muted)' }}>
                                {t('tokenHint')}
                            </p>
                        </div>
                    )}

                    {error && <p style={{ color: 'var(--error)', fontSize: '0.75rem', marginBottom: '1rem', textAlign: 'center' }}>{error}</p>}

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '1.5rem' }}>
                        <input
                            type="checkbox"
                            id="remember"
                            checked={remember}
                            onChange={(e) => setRemember(e.target.checked)}
                            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                        />
                        <label htmlFor="remember" style={{ fontSize: '0.875rem', color: 'var(--text-muted)', cursor: 'pointer', userSelect: 'none' }}>
                            {isServerMode ? t('rememberMe') : t('rememberToken')}
                        </label>
                    </div>

                    <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} disabled={loading}>
                        {loading ? <RefreshCw className="spin" size={18} /> : t('loginBtn')}
                    </button>
                </form>
            </div>
        </div>
    );
};


const ZoneDetail = ({ zone, zones, onSwitchZone, onRefreshZones, zonesLoading, auth, onBack, t, showToast }) => {
    const [tab, setTab] = useState('dns');
    const [records, setRecords] = useState([]);
    const [hostnames, setHostnames] = useState([]);
    const [loading, setLoading] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [error, setError] = useState(null);
    const [expandedRecords, setExpandedRecords] = useState(new Set());
    const [showVerifyModal, setShowVerifyModal] = useState(false);
    const [verifyingSaaS, setVerifyingSaaS] = useState(null);
    const [confirmModal, setConfirmModal] = useState({ show: false, title: '', message: '', onConfirm: null });

    const openConfirm = (title, message, onConfirm) => {
        setConfirmModal({ show: true, title, message, onConfirm });
    };

    // Zone Selector State
    const [showZoneSelector, setShowZoneSelector] = useState(false);
    const zoneSelectorRef = useRef(null);

    useEffect(() => {
        function handleClickOutside(event) {
            if (zoneSelectorRef.current && !zoneSelectorRef.current.contains(event.target)) {
                setShowZoneSelector(false);
            }
        }
        if (showZoneSelector) {
            document.addEventListener("mousedown", handleClickOutside);
        }
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [showZoneSelector]);

    const toggleExpand = (id) => {
        setExpandedRecords(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    // Modal Control
    const [showDNSModal, setShowDNSModal] = useState(false);
    const [editingRecord, setEditingRecord] = useState(null);
    const [newRecord, setNewRecord] = useState({ type: 'A', name: '', content: '', ttl: 1, proxied: true, comment: '', priority: 10, data: {} });
    const [importLoading, setImportLoading] = useState(false);
    const [selectedRecords, setSelectedRecords] = useState(new Set());
    const fileInputRef = useRef(null);

    const initialSaaS = {
        hostname: '',
        ssl: {
            method: 'txt',
            type: 'dv',
            settings: {
                min_tls_version: '1.0'
            }
        },
        custom_origin_server: ''
    };

    const [showSaaSModal, setShowSaaSModal] = useState(false);
    const [editingSaaS, setEditingSaaS] = useState(null);
    const [newSaaS, setNewSaaS] = useState(initialSaaS);

    const startEditSaaS = (h) => {
        setEditingSaaS(h);
        const originValue = h.custom_origin_server || h.custom_origin || h.custom_origin_snihost || '';
        setNewSaaS({
            hostname: h.hostname,
            ssl: {
                method: h.ssl?.method || 'txt',
                type: h.ssl?.type || 'dv',
                settings: {
                    min_tls_version: h.ssl?.settings?.min_tls_version || '1.0'
                }
            },
            custom_origin_server: originValue
        });
        setShowSaaSModal(true);
    };

    const [fallback, setFallback] = useState({ value: '', status: '' });
    const [fallbackLoading, setFallbackLoading] = useState(false);

    const getHeaders = (withType = false) => getAuthHeaders(auth, withType);

    const fetchDNS = async () => {
        setLoading(true);
        try {
            const res = await fetch(`/api/zones/${zone.id}/dns_records`, { headers: getHeaders() });
            const data = await res.json();
            setRecords((data.result || []).sort((a, b) => new Date(b.modified_on) - new Date(a.modified_on)));
        } catch (e) { }
        setLoading(false);
    };

    const fetchHostnames = async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`/api/zones/${zone.id}/custom_hostnames`, { headers: getHeaders() });
            if (!res.ok) {
                const errorData = await res.json();
                throw new Error(errorData.message || 'Failed to fetch custom hostnames');
            }
            const data = await res.json();
            setHostnames(data.result || []);
        } catch (e) {
            console.error("Error fetching custom hostnames:", e);
            setError(e.message || 'Failed to load SaaS hostnames.');
        }
        setLoading(false);
    };

    const fetchFallback = async () => {
        setError(null);
        try {
            const res = await fetch(`/api/zones/${zone.id}/fallback_origin`, { headers: getHeaders() });
            const data = await res.json();
            if (data.result) {
                setFallback({
                    value: data.result.origin || '',
                    status: data.result.status || 'inactive'
                });
            } else {
                setFallback({ value: '', status: 'not_set' });
            }
        } catch (e) {
            setFallback({ value: '', status: 'error' });
        }
    };

    const handleUpdateFallback = async (e) => {
        e.preventDefault();
        setFallbackLoading(true);
        try {
            const res = await fetch(`/api/zones/${zone.id}/fallback_origin`, {
                method: 'PUT',
                headers: getHeaders(true),
                body: JSON.stringify({ origin: fallback.value })
            });
            if (res.ok) {
                fetchFallback();
                showToast(t('updateSuccess'));
            } else {
                const data = await res.json().catch(() => ({}));
                showToast(data.message || t('errorOccurred'), 'error');
            }
        } catch (e) {
            showToast(t('errorOccurred'), 'error');
        }
        setFallbackLoading(false);
    };

    useEffect(() => {
        if (tab === 'dns') {
            fetchDNS();
            setSelectedRecords(new Set()); // Reset selection on tab change
        }
        if (tab === 'saas') {
            fetchHostnames();
            fetchFallback();
        }
    }, [tab, zone.id]);

    const handleDNSSubmit = async (e) => {
        e.preventDefault();
        const method = editingRecord ? 'PATCH' : 'POST';
        const url = `/api/zones/${zone.id}/dns_records${editingRecord ? `?id=${editingRecord.id}` : ''}`;

        // Clean up data for types that don't need it
        const payload = { ...newRecord };
        const structuredTypes = ['SRV', 'CAA', 'URI', 'DS', 'TLSA', 'NAPTR', 'SSHFP', 'HTTPS', 'SVCB'];
        if (!structuredTypes.includes(payload.type)) {
            delete payload.data;
        } else {
            delete payload.content;
            if (payload.type === 'SRV' || payload.type === 'URI') {
                delete payload.priority; // Priority is inside data for SRV/URI
                // Ensure data.name is sync with record name for SRV
                if (payload.type === 'SRV' && payload.name) {
                    payload.data = { ...payload.data, name: payload.name };
                }
            }
        }

        const res = await fetch(url, {
            method,
            headers: getHeaders(true),
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            setShowDNSModal(false);
            setEditingRecord(null);
            fetchDNS();
            showToast(editingRecord ? t('updateSuccess') : t('addSuccess'));
        } else {
            const data = await res.json().catch(() => ({}));
            const isFallbackError = data.errors?.some(e => e.code === 1040);
            showToast(isFallbackError ? t('fallbackError') : (data.errors?.[0]?.message || data.message || t('errorOccurred')), 'error');
        }
    };

    const handleSaaSSubmit = async (e) => {
        e.preventDefault();
        const method = editingSaaS ? 'PATCH' : 'POST';
        const url = `/api/zones/${zone.id}/custom_hostnames${editingSaaS ? `?id=${editingSaaS.id}` : ''}`;

        // Prepare payload correctly
        const payload = {
            hostname: newSaaS.hostname,
            ssl: {
                method: newSaaS.ssl.method,
                type: newSaaS.ssl.type,
                settings: {
                    min_tls_version: newSaaS.ssl.settings.min_tls_version
                }
            }
        };

        if (newSaaS.custom_origin_server && newSaaS.custom_origin_server.trim()) {
            const origin = newSaaS.custom_origin_server.trim();
            payload.custom_origin_server = origin;
            // Usually we want SNI to match the origin server hostname when overriding
            payload.custom_origin_snihost = origin;
        } else if (editingSaaS) {
            // Explicitly clear when editing and choice is back to default
            payload.custom_origin_server = null;
            payload.custom_origin_snihost = null;
        }

        const res = await fetch(url, {
            method,
            headers: getHeaders(true),
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            setShowSaaSModal(false);
            setEditingSaaS(null);
            fetchHostnames();
            showToast(editingSaaS ? t('updateSuccess') : t('addSuccess'));
        } else {
            const data = await res.json().catch(() => ({}));
            showToast(data.message || t('errorOccurred'), 'error');
        }
    };

    const deleteRecord = async (id) => {
        openConfirm(t('confirmTitle'), t('confirmDelete'), async () => {
            const res = await fetch(`/api/zones/${zone.id}/dns_records?id=${id}`, {
                method: 'DELETE',
                headers: getHeaders()
            });
            if (res.ok) {
                fetchDNS();
                showToast(t('deleteSuccess'));
            } else {
                const data = await res.json().catch(() => ({}));
                showToast(data.message || t('errorOccurred'), 'error');
            }
        });
    };

    const deleteSaaS = async (id) => {
        openConfirm(t('confirmTitle'), t('confirmDeleteSaaS'), async () => {
            const res = await fetch(`/api/zones/${zone.id}/custom_hostnames?id=${id}`, {
                method: 'DELETE',
                headers: getHeaders()
            });
            if (res.ok) {
                fetchHostnames();
                showToast(t('deleteSuccess'));
            } else {
                const data = await res.json().catch(() => ({}));
                showToast(data.message || t('errorOccurred'), 'error');
            }
        });
    };

    const toggleProxied = async (record) => {
        if (!['A', 'AAAA', 'CNAME'].includes(record.type)) return;

        // Optimistic update
        const originalStatus = record.proxied;
        setRecords(prev => prev.map(r =>
            r.id === record.id ? { ...r, proxied: !originalStatus } : r
        ));

        try {
            const res = await fetch(`/api/zones/${zone.id}/dns_records?id=${record.id}`, {
                method: 'PATCH',
                headers: getHeaders(true),
                body: JSON.stringify({ proxied: !originalStatus })
            });
            if (!res.ok) {
                // Revert on failure
                setRecords(prev => prev.map(r =>
                    r.id === record.id ? { ...r, proxied: originalStatus } : r
                ));
                const isFallbackError = data.errors?.some(e => e.code === 1040);
                if (isFallbackError) {
                    showToast(t('fallbackError'), 'error');
                } else {
                    showToast(data.errors?.[0]?.message || data.message || t('errorOccurred'), 'error');
                }
            } else {
                // fetchDNS(); // Don't refresh whole list, relied on optimistic update
                showToast(t('updateSuccess'));
            }
        } catch (e) {
            // Revert on error
            setRecords(prev => prev.map(r =>
                r.id === record.id ? { ...r, proxied: originalStatus } : r
            ));
        }
    };

    const startEdit = (record) => {
        setEditingRecord(record);
        setNewRecord({
            type: record.type,
            name: record.name,
            content: record.content,
            ttl: record.ttl,
            proxied: record.proxied,
            comment: record.comment || '',
            priority: record.priority || 10,
            data: record.data || {}
        });
        setShowDNSModal(true);
    };

    const handleExport = async () => {
        try {
            const headers = getHeaders();
            const res = await fetch(`/api/zones/${zone.id}/dns_export`, { headers });
            if (!res.ok) throw new Error('Export failed');

            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dns_records_${zone.name}.txt`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            showToast(t('exportSuccess'));
        } catch (e) {
            showToast(t('errorOccurred'), 'error');
        }
    };

    const handleImport = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        setImportLoading(true);
        const formData = new FormData();
        formData.append('file', file);
        formData.append('proxied', 'true');

        try {
            const res = await fetch(`/api/zones/${zone.id}/dns_import`, {
                method: 'POST',
                headers: getHeaders(), // Don't set Content-Type
                body: formData
            });
            const data = await res.json();
            if (res.ok) {
                showToast(t('importSuccess'));
                fetchDNS();
            } else {
                showToast(data.message || t('errorOccurred'), 'error');
            }
        } catch (e) {
            showToast(t('errorOccurred'), 'error');
        }
        setImportLoading(false);
        e.target.value = ''; // Reset input
    };

    const handleBatchDelete = async () => {
        const count = selectedRecords.size;
        if (count === 0) return;
        openConfirm(t('confirmTitle'), t('confirmBatchDelete').replace('{count}', count), async () => {
            setLoading(true);
            try {
                const res = await fetch(`/api/zones/${zone.id}/dns_batch`, {
                    method: 'POST',
                    headers: getHeaders(true),
                    body: JSON.stringify({
                        deletes: Array.from(selectedRecords).map(id => ({ id }))
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    showToast(t('deleteSuccess'));
                    setSelectedRecords(new Set());
                    fetchDNS();
                } else {
                    showToast(data.message || t('errorOccurred'), 'error');
                }
            } catch (e) {
                showToast(t('errorOccurred'), 'error');
            }
            setLoading(false);
        });
    };

    const toggleSelectAll = () => {
        if (selectedRecords.size === filteredRecords.length) {
            setSelectedRecords(new Set());
        } else {
            setSelectedRecords(new Set(filteredRecords.map(r => r.id)));
        }
    };

    const toggleSelect = (id) => {
        setSelectedRecords(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const filteredRecords = records.filter(r =>
        r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        r.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
        r.type.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const filteredSaaS = hostnames.filter(h =>
        h.hostname.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="container">
            <div style={{ marginBottom: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', position: 'relative' }} ref={zoneSelectorRef}>
                    <div style={{ padding: '0.25rem', background: '#fff7ed', borderRadius: '8px' }}>
                        <Globe size={24} color="var(--primary)" />
                    </div>

                    <div
                        onClick={() => setShowZoneSelector(!showZoneSelector)}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', cursor: 'pointer', userSelect: 'none' }}
                        title={t('switchZone')}
                    >
                        <h1 style={{ cursor: 'pointer', fontSize: '1.5rem', margin: 0, lineHeight: 1 }}>{zone.name}</h1>
                        <ChevronDown size={24} color="var(--text-muted)" style={{ transform: showZoneSelector ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }} />
                    </div>

                    {showZoneSelector && (
                        <div className="glass-card fade-in" style={{
                            position: 'absolute',
                            top: '120%',
                            left: 0,
                            zIndex: 100,
                            maxHeight: '400px',
                            overflowY: 'auto',
                            minWidth: '280px',
                            padding: '0.5rem',
                            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
                        }}>
                            <div style={{ padding: '0.5rem 0.75rem', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', borderBottom: '1px solid var(--border)', marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span>{t('yourDomains')}</span>
                                <button className="btn btn-outline" style={{ padding: '2px 6px', height: 'auto', fontSize: '0.7rem' }} onClick={(e) => { e.stopPropagation(); onRefreshZones(); }}>
                                    <RefreshCw size={10} className={zonesLoading ? 'spin' : ''} />
                                    {t('refresh')}
                                </button>
                            </div>
                            {zones.map(z => (
                                <div
                                    key={z.id}
                                    onClick={() => {
                                        onSwitchZone(z);
                                        setShowZoneSelector(false);
                                    }}
                                    style={{
                                        padding: '0.5rem 0.75rem',
                                        cursor: 'pointer',
                                        borderRadius: '6px',
                                        background: z.id === zone.id ? '#fff7ed' : 'transparent',
                                        color: z.id === zone.id ? 'var(--primary)' : 'var(--text)',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'space-between',
                                        gap: '8px',
                                        marginBottom: '2px',
                                        transition: 'all 0.1s'
                                    }}
                                    onMouseEnter={e => { if (z.id !== zone.id) e.currentTarget.style.background = '#f9fafb'; }}
                                    onMouseLeave={e => { if (z.id !== zone.id) e.currentTarget.style.background = 'transparent'; }}
                                >
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <span style={{ fontWeight: z.id === zone.id ? 600 : 400, fontSize: '0.875rem' }}>{z.name}</span>
                                        <span className={`badge ${z.status === 'active' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '0.6rem', padding: '1px 4px' }}>
                                            {t('status' + z.status.charAt(0).toUpperCase() + z.status.slice(1))}
                                        </span>
                                    </div>
                                    {z.id === zone.id && <CheckCircle size={14} />}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            <div style={{ display: 'flex', gap: '2rem', borderBottom: '1px solid var(--border)', marginBottom: '1.5rem', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                <button
                    className="btn"
                    style={{
                        background: 'transparent',
                        color: tab === 'dns' ? 'var(--primary)' : 'var(--text-muted)',
                        borderBottom: tab === 'dns' ? '2px solid var(--primary)' : 'none',
                        borderRadius: 0,
                        padding: '0.75rem 0',
                        fontWeight: tab === 'dns' ? '700' : '500'
                    }}
                    onClick={() => setTab('dns')}
                >
                    {t('dnsRecords')}
                </button>
                <button
                    className="btn"
                    style={{
                        background: 'transparent',
                        color: tab === 'saas' ? 'var(--primary)' : 'var(--text-muted)',
                        borderBottom: tab === 'saas' ? '2px solid var(--primary)' : 'none',
                        borderRadius: 0,
                        padding: '0.75rem 0',
                        fontWeight: tab === 'saas' ? '700' : '500'
                    }}
                    onClick={() => setTab('saas')}
                >
                    {t('saasHostnames')}
                </button>
            </div>

            <div className="glass-card" style={{ padding: '1.25rem', overflow: 'hidden' }}>
                <div className="flex-stack header-stack" style={{ marginBottom: '1.0rem', flexWrap: 'wrap', gap: '1rem' }}>
                    <div className="header-top-row" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                        <h2 style={{ margin: 0, whiteSpace: 'nowrap' }}>{tab === 'dns' ? t('dnsRecords') : t('saasHostnames')}</h2>
                        <div className="header-actions" style={{ display: 'flex', gap: '0.5rem' }}>
                            {tab === 'dns' && (
                                <>
                                    {selectedRecords.size > 0 && (
                                        <button className="btn" style={{ background: 'var(--error)', color: 'white', border: 'none' }} onClick={handleBatchDelete}>
                                            <Trash2 size={16} />
                                            <span className="btn-text">{t('batchDelete')} ({selectedRecords.size})</span>
                                        </button>
                                    )}
                                    <input
                                        type="file"
                                        ref={fileInputRef}
                                        style={{ display: 'none' }}
                                        onChange={handleImport}
                                        accept=".txt"
                                    />
                                    <button className="btn btn-outline" onClick={() => fileInputRef.current.click()} disabled={importLoading}>
                                        <Upload size={16} className={importLoading ? 'spin' : ''} />
                                        <span className="btn-text">{t('import')}</span>
                                    </button>
                                    <button className="btn btn-outline" onClick={handleExport}>
                                        <Download size={16} />
                                        <span className="btn-text">{t('export')}</span>
                                    </button>
                                </>
                            )}
                            <button
                                className="btn btn-outline"
                                onClick={() => tab === 'dns' ? fetchDNS() : fetchHostnames()}
                                disabled={loading}
                            >
                                <RefreshCw size={16} className={loading ? 'spin' : ''} />
                                <span className="btn-text">{t('refresh')}</span>
                            </button>
                            {tab === 'dns' ? (
                                <button className="btn btn-primary" onClick={() => { setEditingRecord(null); setShowDNSModal(true); setNewRecord({ type: 'A', name: '', content: '', ttl: 1, proxied: true, comment: '', priority: 10, data: {} }); }}>
                                    <Plus size={16} /> <span className="btn-text">{t('addRecord')}</span>
                                </button>
                            ) : (
                                <button className="btn btn-primary" onClick={() => {
                                    setEditingSaaS(null);
                                    setNewSaaS(initialSaaS);
                                    setShowSaaSModal(true);
                                }}>
                                    <Plus size={16} /> <span className="btn-text">{t('addSaaS')}</span>
                                </button>
                            )}
                        </div>
                    </div>
                    <div style={{ position: 'relative', width: '100%', maxWidth: '100%' }} className="search-container">
                        <input
                            type="text"
                            placeholder={t('searchPlaceholder')}
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            style={{ paddingLeft: '32px', height: '36px', fontSize: '0.8125rem', width: '100%' }}
                        />
                        <Search size={14} style={{ position: 'absolute', left: '10px', top: '11px', color: 'var(--text-muted)' }} />
                    </div>
                </div>

                <div className="table-container">
                    {tab === 'dns' ? (
                        <>
                            <table className="data-table desktop-only">
                                <thead>
                                    <tr>
                                        <th style={{ width: '40px' }}>
                                            <input
                                                type="checkbox"
                                                checked={filteredRecords.length > 0 && selectedRecords.size === filteredRecords.length}
                                                onChange={toggleSelectAll}
                                                className="record-checkbox"
                                            />
                                        </th>
                                        <th>{t('type')}</th>
                                        <th>{t('name')} / {t('comment')}</th>
                                        <th>{t('content')}</th>
                                        <th>{t('ttl')}</th>
                                        <th>{t('proxied')}</th>
                                        <th>{t('actions')}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredRecords.map(record => (
                                        <tr key={record.id}>
                                            <td>
                                                <input
                                                    type="checkbox"
                                                    checked={selectedRecords.has(record.id)}
                                                    onChange={() => toggleSelect(record.id)}
                                                    className="record-checkbox"
                                                />
                                            </td>
                                            <td><span className="badge badge-blue">{record.type}</span></td>
                                            <td>
                                                <div style={{ fontWeight: 600 }}>{record.name}</div>
                                                {record.comment && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{record.comment}</div>}
                                            </td>
                                            <td className="truncate-mobile" style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{record.content}</td>
                                            <td style={{ fontSize: '0.8125rem' }}>{record.ttl === 1 ? t('ttlAuto') : record.ttl}</td>
                                            <td>
                                                {['A', 'AAAA', 'CNAME'].includes(record.type) ? (
                                                    <label className="toggle-switch">
                                                        <input
                                                            type="checkbox"
                                                            checked={record.proxied}
                                                            onChange={() => toggleProxied(record)}
                                                        />
                                                        <span className="slider"></span>
                                                    </label>
                                                ) : (
                                                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', opacity: 0.5 }}>—</span>
                                                )}
                                            </td>
                                            <td>
                                                <div style={{ display: 'flex', gap: '4px' }}>
                                                    <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => startEdit(record)}>
                                                        <Edit2 size={16} color="var(--primary)" />
                                                    </button>
                                                    <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => deleteRecord(record.id)}>
                                                        <Trash2 size={16} color="var(--error)" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            <div className="mobile-only">
                                {filteredRecords.map(record => (
                                    <div key={record.id} className="record-card">
                                        {/* 上部 0.5：记录类型 */}
                                        <div className="record-type-row">
                                            <span className="dns-type-label">{record.type}</span>
                                        </div>
                                        {/* 下部 1.0：主内容 */}
                                        <div className="record-header" onClick={() => toggleExpand(record.id)}>
                                            <div className="record-header-main">
                                                <div className="dns-selection" onClick={e => e.stopPropagation()}>
                                                    <input
                                                        type="checkbox"
                                                        checked={selectedRecords.has(record.id)}
                                                        onChange={() => toggleSelect(record.id)}
                                                        className="record-checkbox"
                                                    />
                                                </div>
                                                <div className="dns-name-wrapper">
                                                    <div className="dns-name">{record.name}</div>
                                                    {record.comment && <div className="dns-comment">{record.comment}</div>}
                                                </div>
                                            </div>
                                            <div className="record-actions-inline" onClick={e => e.stopPropagation()}>
                                                {['A', 'AAAA', 'CNAME'].includes(record.type) && (
                                                    <label className="toggle-switch" style={{ transform: 'scale(0.8)', margin: 0 }}>
                                                        <input
                                                            type="checkbox"
                                                            checked={record.proxied}
                                                            onChange={() => toggleProxied(record)}
                                                        />
                                                        <span className="slider"></span>
                                                    </label>
                                                )}
                                                <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => startEdit(record)}>
                                                    <Edit2 size={16} color="var(--primary)" />
                                                </button>
                                                <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => deleteRecord(record.id)}>
                                                    <Trash2 size={16} color="var(--error)" />
                                                </button>
                                            </div>
                                        </div>
                                        {expandedRecords.has(record.id) && (
                                            <div className="record-details">
                                                <div className="detail-row" style={{ alignItems: 'stretch' }}>
                                                    <div className="record-content-cell" title={record.content} onClick={(e) => {
                                                        e.stopPropagation();
                                                        navigator.clipboard.writeText(record.content);
                                                        showToast(t('copied'));
                                                    }}>
                                                        {record.content}
                                                    </div>
                                                    <div className="ttl-box">
                                                        <span className="ttl-label">TTL</span>
                                                        <span className="ttl-value">{record.ttl === 1 ? t('ttlAuto') : record.ttl}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <>
                            <div className="glass-card" style={{ padding: '1.25rem', marginBottom: '1.5rem', background: '#f8fafc' }}>
                                <div className="flex-stack">
                                    <div style={{ flex: 1 }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.5rem' }}>
                                            <h3 style={{ fontSize: '0.875rem', margin: 0 }}>{t('fallbackOrigin')}</h3>
                                            <span className={`badge ${fallback.status === 'active' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '0.65rem' }}>
                                                {t(fallback.status) || 'N/A'}
                                            </span>
                                        </div>
                                        <div style={{ display: 'flex', gap: '8px' }}>
                                            <input
                                                type="text"
                                                value={fallback.value || ''}
                                                onChange={e => setFallback({ ...fallback, value: e.target.value })}
                                                placeholder={t('fallbackOriginPlaceholder')}
                                                style={{ height: '36px', fontSize: '0.8125rem', maxWidth: '300px' }}
                                            />
                                            <button
                                                className="btn btn-primary"
                                                onClick={handleUpdateFallback}
                                                disabled={fallbackLoading}
                                                style={{ height: '36px', padding: '0 1rem', whiteSpace: 'nowrap', flexShrink: 0 }}
                                            >
                                                {fallbackLoading ? <RefreshCw className="spin" size={14} /> : t('updateFallback')}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <table className="data-table desktop-only">
                                <thead>
                                    <tr>
                                        <th>{t('hostname')}</th>
                                        <th>{t('status')}</th>
                                        <th>{t('sslStatus')}</th>
                                        <th>{t('originServer')}</th>
                                        <th>{t('actions')}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredSaaS.map(h => (
                                        <tr key={h.id} className="compact-row">
                                            <td style={{ fontWeight: 600 }}>{h.hostname}</td>
                                            <td>
                                                <span className={`badge ${h.status === 'active' ? 'badge-green' : 'badge-orange'}`}>
                                                    {t(h.status)}
                                                </span>
                                            </td>
                                            <td>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                    <span className={`badge ${h.ssl?.status === 'active' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '0.75rem' }}>
                                                        {t(h.ssl?.status) || 'N/A'}
                                                    </span>
                                                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', background: '#f1f5f9', padding: '1px 4px', borderRadius: '4px', textTransform: 'uppercase' }}>
                                                        {h.ssl?.method}
                                                    </span>
                                                </div>
                                            </td>
                                            <td>
                                                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                    <Server size={12} />
                                                    <span>{h.custom_origin_server || h.custom_origin_snihost || h.custom_origin || t('defaultOrigin')}</span>
                                                </div>
                                            </td>
                                            <td>
                                                <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                                                    <div style={{ width: '32px', display: 'flex', justifyContent: 'flex-start' }}>
                                                        {(h.ssl?.status !== 'active' || h.ownership_verification) && (
                                                            <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => { setVerifyingSaaS(h); setShowVerifyModal(true); }} title={t('verificationRecords')}>
                                                                <AlertCircle size={16} color="#f59e0b" />
                                                            </button>
                                                        )}
                                                    </div>
                                                    <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => startEditSaaS(h)}>
                                                        <Edit2 size={16} color="var(--primary)" />
                                                    </button>
                                                    <button className="btn btn-outline" style={{ padding: '0.4rem', border: 'none' }} onClick={() => deleteSaaS(h.id)}>
                                                        <Trash2 size={16} color="var(--error)" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            <div className="mobile-only">
                                {filteredSaaS.map(h => (
                                    <div key={h.id} className="record-card" style={{ padding: '0.875rem', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                        {/* Row 1: Hostname & Origin */}
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
                                            <div style={{ fontWeight: 600, fontSize: '0.9375rem', color: 'var(--text)', wordBreak: 'break-all', flex: 1 }}>{h.hostname}</div>
                                            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', background: '#f8fafc', padding: '2px 6px', borderRadius: '4px', whiteSpace: 'nowrap' }}>
                                                <Server size={10} />
                                                <span>{h.custom_origin_server || h.custom_origin_snihost || h.custom_origin || t('defaultOrigin')}</span>
                                            </div>
                                        </div>

                                        {/* Row 2: Statuses & Actions */}
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                                            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Host:</span>
                                                    <span className={`badge ${h.status === 'active' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '0.6rem', padding: '1px 4px' }}>{t(h.status)}</span>
                                                </div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                    <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>SSL:</span>
                                                    <span className={`badge ${h.ssl?.status === 'active' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '0.6rem', padding: '1px 4px' }}>
                                                        {t(h.ssl?.status) || 'N/A'}
                                                    </span>
                                                    <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)', textTransform: 'uppercase', opacity: 0.8 }}>{h.ssl?.method}</span>
                                                </div>
                                            </div>
                                            <div style={{ display: 'flex', gap: '2px', alignItems: 'center' }}>
                                                {(h.ssl?.status !== 'active' || h.ownership_verification) && (
                                                    <button className="btn btn-outline" style={{ padding: '0.35rem', border: 'none' }} onClick={() => { setVerifyingSaaS(h); setShowVerifyModal(true); }}>
                                                        <AlertCircle size={15} color="#f59e0b" />
                                                    </button>
                                                )}
                                                <button className="btn btn-outline" style={{ padding: '0.35rem', border: 'none' }} onClick={() => startEditSaaS(h)}>
                                                    <Edit2 size={15} color="var(--primary)" />
                                                </button>
                                                <button className="btn btn-outline" style={{ padding: '0.35rem', border: 'none' }} onClick={() => deleteSaaS(h.id)}>
                                                    <Trash2 size={15} color="var(--error)" />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* DNS Modal */}
            {showDNSModal && (
                <div
                    style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 }}
                    onClick={(e) => { if (e.target === e.currentTarget) setShowDNSModal(false); }}
                >
                    <div className="glass-card fade-in" style={{ padding: '2rem', maxWidth: '450px', width: '90%', position: 'relative' }}>
                        <h2 style={{ marginBottom: '1.5rem' }}>{editingRecord ? t('editRecord') : t('addModalTitle')}</h2>
                        <form onSubmit={handleDNSSubmit}>
                            <div className="input-row">
                                <label>{t('type')}</label>
                                <div style={{ flex: 1 }}>
                                    <CustomSelect
                                        value={newRecord.type}
                                        onChange={(e) => {
                                            const newType = e.target.value;
                                            const proxyableTypes = ['A', 'AAAA', 'CNAME'];
                                            setNewRecord({
                                                ...newRecord,
                                                type: newType,
                                                proxied: proxyableTypes.includes(newType) ? newRecord.proxied : false
                                            });
                                        }}
                                        options={['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'URI', 'CAA', 'DS', 'TLSA', 'CERT', 'DNSKEY', 'HTTPS', 'LOC', 'NAPTR', 'PTR', 'SMIMEA', 'SSHFP', 'SVCB'].map(t => ({ value: t, label: t }))}
                                    />
                                </div>
                            </div>
                            <div className="input-row">
                                <label>{t('name')}</label>
                                <input type="text" value={newRecord.name} onChange={e => setNewRecord({ ...newRecord, name: e.target.value })} placeholder={newRecord.type === 'SRV' ? '_sip._tcp' : '@'} required />
                            </div>

                            {!['SRV', 'CAA', 'URI', 'DS', 'TLSA', 'NAPTR', 'SSHFP', 'HTTPS', 'SVCB'].includes(newRecord.type) && (
                                <div className="input-row">
                                    <label>{t('content')}</label>
                                    <input type="text" value={newRecord.content} onChange={e => setNewRecord({ ...newRecord, content: e.target.value })} placeholder={newRecord.type === 'LOC' ? '33 40 31 N 106 28 29 W 10m' : 'Value'} required />
                                </div>
                            )}

                            {newRecord.type === 'SRV' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('service')}</label>
                                        <input type="text" value={newRecord.data?.service || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, service: e.target.value } })} placeholder="_sip" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('protocol')}</label>
                                        <input type="text" value={newRecord.data?.proto || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, proto: e.target.value } })} placeholder="_tcp" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('priority')}</label>
                                        <input type="number" value={newRecord.data?.priority || 10} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, priority: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('weight')}</label>
                                        <input type="number" value={newRecord.data?.weight || 5} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, weight: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('port')}</label>
                                        <input type="number" value={newRecord.data?.port || 5060} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, port: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('target')}</label>
                                        <input type="text" value={newRecord.data?.target || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, target: e.target.value } })} placeholder="sipserver.example.com" required />
                                    </div>
                                </>
                            )}

                            {newRecord.type === 'URI' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('priority')}</label>
                                        <input type="number" value={newRecord.data?.priority || 10} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, priority: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('weight')}</label>
                                        <input type="number" value={newRecord.data?.weight || 5} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, weight: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('target')}</label>
                                        <input type="text" value={newRecord.data?.target || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, target: e.target.value } })} placeholder="https://example.com" required />
                                    </div>
                                </>
                            )}

                            {newRecord.type === 'CAA' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('flags')}</label>
                                        <input type="number" value={newRecord.data?.flags || 0} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, flags: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('tag')}</label>
                                        <CustomSelect
                                            value={newRecord.data?.tag || 'issue'}
                                            onChange={(e) => setNewRecord({ ...newRecord, data: { ...newRecord.data, tag: e.target.value } })}
                                            options={[
                                                { value: 'issue', label: 'issue' },
                                                { value: 'issuewild', label: 'issuewild' },
                                                { value: 'iodef', label: 'iodef' }
                                            ]}
                                        />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('value')}</label>
                                        <input type="text" value={newRecord.data?.value || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, value: e.target.value } })} placeholder="comodoca.com" required />
                                    </div>
                                </>
                            )}

                            {newRecord.type === 'DS' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('keyTag')}</label>
                                        <input type="number" value={newRecord.data?.key_tag || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, key_tag: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('algorithm')}</label>
                                        <input type="number" value={newRecord.data?.algorithm || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, algorithm: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('digestType')}</label>
                                        <input type="number" value={newRecord.data?.digest_type || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, digest_type: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('digest')}</label>
                                        <input type="text" value={newRecord.data?.digest || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, digest: e.target.value } })} placeholder={t('digest')} required />
                                    </div>
                                </>
                            )}

                            {newRecord.type === 'TLSA' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('usage')}</label>
                                        <input type="number" value={newRecord.data?.usage || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, usage: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('selector')}</label>
                                        <input type="number" value={newRecord.data?.selector || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, selector: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('matchingType')}</label>
                                        <input type="number" value={newRecord.data?.matching_type || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, matching_type: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('certificate')}</label>
                                        <input type="text" value={newRecord.data?.certificate || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, certificate: e.target.value } })} placeholder={t('certificate')} required />
                                    </div>
                                </>
                            )}

                            {newRecord.type === 'NAPTR' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('order')}</label>
                                        <input type="number" value={newRecord.data?.order || 100} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, order: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('preference')}</label>
                                        <input type="number" value={newRecord.data?.preference || 10} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, preference: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('flags')}</label>
                                        <input type="text" value={newRecord.data?.flags || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, flags: e.target.value } })} placeholder="S" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('service')}</label>
                                        <input type="text" value={newRecord.data?.service || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, service: e.target.value } })} placeholder="http+E2U" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('regex')}</label>
                                        <input type="text" value={newRecord.data?.regex || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, regex: e.target.value } })} placeholder={t('regex')} />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('replacement')}</label>
                                        <input type="text" value={newRecord.data?.replacement || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, replacement: e.target.value } })} placeholder="." />
                                    </div>
                                </>
                            )}

                            {newRecord.type === 'SSHFP' && (
                                <>
                                    <div className="input-row">
                                        <label>{t('algorithm')}</label>
                                        <input type="number" value={newRecord.data?.algorithm || 4} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, algorithm: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('type')}</label>
                                        <input type="number" value={newRecord.data?.type || 2} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, type: parseInt(e.target.value) } })} min="0" max="255" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('fingerprint')}</label>
                                        <input type="text" value={newRecord.data?.fingerprint || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, fingerprint: e.target.value } })} placeholder={t('fingerprint')} required />
                                    </div>
                                </>
                            )}

                            {(newRecord.type === 'HTTPS' || newRecord.type === 'SVCB') && (
                                <>
                                    <div className="input-row">
                                        <label>{t('priority')}</label>
                                        <input type="number" value={newRecord.data?.priority || 1} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, priority: parseInt(e.target.value) } })} min="0" max="65535" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('target')}</label>
                                        <input type="text" value={newRecord.data?.target || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, target: e.target.value } })} placeholder="example.com" required />
                                    </div>
                                    <div className="input-row">
                                        <label>{t('value')}</label>
                                        <input type="text" value={newRecord.data?.value || ''} onChange={e => setNewRecord({ ...newRecord, data: { ...newRecord.data, value: e.target.value } })} placeholder="alpn=h3,h2" required />
                                    </div>
                                </>
                            )}
                            <div className="input-row">
                                <label>{t('ttl')}</label>
                                <div style={{ flex: 1 }}>
                                    <CustomSelect
                                        value={newRecord.ttl}
                                        onChange={(e) => setNewRecord({ ...newRecord, ttl: parseInt(e.target.value) })}
                                        options={[
                                            { value: 1, label: t('ttlAuto') },
                                            { value: 60, label: t('ttl1min') },
                                            { value: 120, label: t('ttl2min') },
                                            { value: 300, label: t('ttl5min') },
                                            { value: 600, label: t('ttl10min') },
                                            { value: 900, label: t('ttl15min') },
                                            { value: 1800, label: t('ttl30min') },
                                            { value: 3600, label: t('ttl1h') },
                                            { value: 7200, label: t('ttl2h') },
                                            { value: 18000, label: t('ttl5h') },
                                            { value: 43200, label: t('ttl12h') },
                                            { value: 86400, label: t('ttl1d') }
                                        ]}
                                    />
                                </div>
                            </div>
                            {['MX'].includes(newRecord.type) && (
                                <div className="input-row">
                                    <label>{t('priority')}</label>
                                    <input type="number" value={newRecord.priority} onChange={e => setNewRecord({ ...newRecord, priority: parseInt(e.target.value) })} min="0" max="65535" required />
                                </div>
                            )}
                            <div className="input-row">
                                <label>{t('comment')}</label>
                                <input
                                    type="text"
                                    value={newRecord.comment || ''}
                                    onChange={e => setNewRecord({ ...newRecord, comment: e.target.value })}
                                    placeholder={t('comment')}
                                />
                            </div>
                            {['A', 'AAAA', 'CNAME'].includes(newRecord.type) && (
                                <div className="input-row" style={{ alignItems: 'center' }}>
                                    <label>{t('proxied')}</label>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <label className="toggle-switch" style={{ margin: 0 }}>
                                            <input
                                                type="checkbox"
                                                checked={newRecord.proxied}
                                                onChange={(e) => setNewRecord({ ...newRecord, proxied: e.target.checked })}
                                            />
                                            <span className="slider"></span>
                                        </label>
                                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t('proxiedHint')}</span>
                                    </div>
                                </div>
                            )}
                            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem' }}>
                                <button type="button" className="btn btn-outline" style={{ flex: 1 }} onClick={() => setShowDNSModal(false)}>{t('cancel')}</button>
                                <button type="submit" className="btn btn-primary" style={{ flex: 1 }}>{t('save')}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* SaaS Modal */}
            {showSaaSModal && (
                <div
                    style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 }}
                    onClick={(e) => { if (e.target === e.currentTarget) { setShowSaaSModal(false); setEditingSaaS(null); setNewSaaS(initialSaaS); } }}
                >
                    <div className="glass-card fade-in" style={{ padding: '2rem', maxWidth: '450px', width: '90%', position: 'relative' }}>
                        <h2 style={{ marginBottom: '1.5rem' }}>{editingSaaS ? t('editSaaS') : t('addSaaS')}</h2>
                        <form onSubmit={handleSaaSSubmit}>
                            <div className="input-row">
                                <label>{t('hostname')}</label>
                                <input
                                    type="text"
                                    value={newSaaS.hostname}
                                    onChange={e => setNewSaaS({ ...newSaaS, hostname: e.target.value })}
                                    placeholder={t('hostnamePlaceholder')}
                                    required
                                />
                            </div>

                            <div className="input-row">
                                <label>{t('minTlsVersion')}</label>
                                <div style={{ flex: 1 }}>
                                    <CustomSelect
                                        value={newSaaS.ssl.settings.min_tls_version}
                                        onChange={(e) => setNewSaaS({ ...newSaaS, ssl: { ...newSaaS.ssl, settings: { ...newSaaS.ssl.settings, min_tls_version: e.target.value } } })}
                                        options={[
                                            { value: '1.0', label: t('tlsDefault') },
                                            { value: '1.1', label: 'TLS 1.1' },
                                            { value: '1.2', label: 'TLS 1.2' },
                                            { value: '1.3', label: 'TLS 1.3' }
                                        ]}
                                    />
                                </div>
                            </div>

                            <div className="input-row">
                                <label>{t('verifyMethod')}</label>
                                <div style={{ flex: 1 }}>
                                    <CustomSelect
                                        value={newSaaS.ssl.method}
                                        onChange={(e) => setNewSaaS({ ...newSaaS, ssl: { ...newSaaS.ssl, method: e.target.value } })}
                                        options={[
                                            { value: 'txt', label: t('sslMethodTxt') + ` (${t('recommended')})` },
                                            { value: 'http', label: t('sslMethodHttp') }
                                        ]}
                                    />
                                </div>
                            </div>

                            <div className="input-row">
                                <label>{t('originServer')}</label>
                                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    <CustomSelect
                                        value={newSaaS.custom_origin_server ? 'custom' : 'default'}
                                        onChange={(e) => {
                                            if (e.target.value === 'default') {
                                                setNewSaaS({ ...newSaaS, custom_origin_server: '' });
                                            } else {
                                                setNewSaaS({ ...newSaaS, custom_origin_server: ' ' }); // space to trigger
                                            }
                                        }}
                                        options={[
                                            { value: 'default', label: t('defaultOrigin') },
                                            { value: 'custom', label: t('customOrigin') }
                                        ]}
                                    />
                                    {newSaaS.custom_origin_server !== '' && (
                                        <input
                                            type="text"
                                            value={newSaaS.custom_origin_server === ' ' ? '' : newSaaS.custom_origin_server}
                                            onChange={e => setNewSaaS({ ...newSaaS, custom_origin_server: e.target.value })}
                                            placeholder={t('originPlaceholder')}
                                            required
                                        />
                                    )}
                                </div>
                            </div>

                            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem' }}>
                                <button type="button" className="btn btn-outline" style={{ flex: 1 }} onClick={() => {
                                    setShowSaaSModal(false);
                                    setEditingSaaS(null);
                                    setNewSaaS(initialSaaS);
                                }}>{t('cancel')}</button>
                                <button type="submit" className="btn btn-primary" style={{ flex: 1 }}>{t('save')}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Confirm Modal */}
            {confirmModal.show && (
                <div
                    style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 2000 }}
                    onClick={(e) => { if (e.target === e.currentTarget) setConfirmModal({ ...confirmModal, show: false }); }}
                >
                    <div className="glass-card fade-in" style={{ padding: '2rem', maxWidth: '400px', width: '90%', textAlign: 'center' }}>
                        <div style={{ width: '48px', height: '48px', background: '#fff5f5', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1.25rem' }}>
                            <AlertCircle size={24} color="var(--error)" />
                        </div>
                        <h2 style={{ marginBottom: '0.75rem' }}>{confirmModal.title}</h2>
                        <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '2rem', lineHeight: '1.6' }}>{confirmModal.message}<br />{t('confirmDeleteText')}</p>
                        <div style={{ display: 'flex', gap: '0.75rem' }}>
                            <button className="btn btn-outline" style={{ flex: 1 }} onClick={() => setConfirmModal({ ...confirmModal, show: false })}>{t('cancel')}</button>
                            <button className="btn btn-primary" style={{ flex: 1, background: 'var(--error)' }} onClick={() => {
                                confirmModal.onConfirm();
                                setConfirmModal({ ...confirmModal, show: false });
                            }}>{t('yes')}</button>
                        </div>
                    </div>
                </div>
            )}
            {/* Verification Modal */}
            {showVerifyModal && verifyingSaaS && (
                <div
                    style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.4)', backdropFilter: 'blur(4px)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 }}
                    onClick={(e) => { if (e.target === e.currentTarget) setShowVerifyModal(false); }}
                >
                    <div className="glass-card fade-in" style={{ padding: '2rem', maxWidth: '600px', width: '90%', maxHeight: '90vh', overflowY: 'auto' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                            <h2 style={{ margin: 0 }}>{t('verificationRecords')}</h2>
                            <button className="btn btn-outline" style={{ padding: '4px', border: 'none' }} onClick={() => setShowVerifyModal(false)}>
                                <X size={20} />
                            </button>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                            {verifyingSaaS.ownership_verification && (
                                <div>
                                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.75rem', textTransform: 'uppercase' }}>{t('ownership')}</h4>
                                    <div style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                        <div>
                                            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyType')}</p>
                                            <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px' }}>{verifyingSaaS.ownership_verification.type}</code>
                                        </div>
                                        <div>
                                            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyName')}</p>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', flex: 1 }}>{verifyingSaaS.ownership_verification.name}</code>
                                                <button className="btn btn-outline" style={{ padding: '6px' }} onClick={() => { navigator.clipboard.writeText(verifyingSaaS.ownership_verification.name); showToast(t('copied')); }}>
                                                    <Copy size={14} />
                                                </button>
                                            </div>
                                        </div>
                                        <div>
                                            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyValue')}</p>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', flex: 1 }}>{verifyingSaaS.ownership_verification.value}</code>
                                                <button className="btn btn-outline" style={{ padding: '6px' }} onClick={() => { navigator.clipboard.writeText(verifyingSaaS.ownership_verification.value); showToast(t('copied')); }}>
                                                    <Copy size={14} />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {(verifyingSaaS.ssl?.validation_records?.length > 0 || verifyingSaaS.ssl?.cname) && (
                                <div>
                                    <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.75rem', textTransform: 'uppercase' }}>{t('sslValidation')}</h4>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                        {verifyingSaaS.ssl.validation_records?.map((rec, idx) => (
                                            <div key={idx} style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                    <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: '4px' }}>TXT</code>
                                                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t('verifyMethod')}</span>
                                                </div>
                                                <div>
                                                    <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyName')}</p>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                        <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', flex: 1 }}>{rec.txt_name}</code>
                                                        <button className="btn btn-outline" style={{ padding: '6px' }} onClick={() => { navigator.clipboard.writeText(rec.txt_name); showToast(t('copied')); }}>
                                                            <Copy size={14} />
                                                        </button>
                                                    </div>
                                                </div>
                                                <div>
                                                    <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyValue')}</p>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                        <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', flex: 1 }}>{rec.txt_value}</code>
                                                        <button className="btn btn-outline" style={{ padding: '6px' }} onClick={() => { navigator.clipboard.writeText(rec.txt_value); showToast(t('copied')); }}>
                                                            <Copy size={14} />
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                        {verifyingSaaS.ssl.cname && (
                                            <div style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                    <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: '4px' }}>CNAME</code>
                                                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t('verifyMethod')}</span>
                                                </div>
                                                <div>
                                                    <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyName')}</p>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                        <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', flex: 1 }}>{verifyingSaaS.hostname}</code>
                                                        <button className="btn btn-outline" style={{ padding: '6px' }} onClick={() => { navigator.clipboard.writeText(verifyingSaaS.hostname); showToast(t('copied')); }}>
                                                            <Copy size={14} />
                                                        </button>
                                                    </div>
                                                </div>
                                                <div>
                                                    <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{t('verifyValue')}</p>
                                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                        <code style={{ fontSize: '0.8125rem', background: '#fff', border: '1px solid var(--border)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', flex: 1 }}>{verifyingSaaS.ssl.cname_target}</code>
                                                        <button className="btn btn-outline" style={{ padding: '6px' }} onClick={() => { navigator.clipboard.writeText(verifyingSaaS.ssl.cname_target); showToast(t('copied')); }}>
                                                            <Copy size={14} />
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>

                    </div>
                </div>
            )}
        </div >
    );
};

const App = () => {
    const { t, lang, changeLang, toggleLang } = useTranslate();
    const [auth, setAuth] = useState(null);
    const [showAccountSelector, setShowAccountSelector] = useState(false);
    const accountSelectorRef = useRef(null);
    const [zones, setZones] = useState([]);
    const [selectedZone, setSelectedZone] = useState(null);
    const [loading, setLoading] = useState(false);
    const [toast, setToast] = useState(null);
    const toastTimer = useRef(null);

    // Close dropdown when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (accountSelectorRef.current && !accountSelectorRef.current.contains(event.target)) {
                setShowAccountSelector(false);
            }
        };

        const handleScroll = () => {
            if (showAccountSelector) setShowAccountSelector(false);
        };

        document.addEventListener('mousedown', handleClickOutside);
        window.addEventListener('scroll', handleScroll, { capture: true });

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
            window.removeEventListener('scroll', handleScroll, { capture: true });
        };
    }, [showAccountSelector]);

    const showToast = (message, type = 'success') => {
        if (toastTimer.current) clearTimeout(toastTimer.current);
        setToast({ message, type, id: Date.now() });
        toastTimer.current = setTimeout(() => setToast(null), 3000);
    };

    const fetchZones = async (credentials) => {
        setLoading(true);
        const headers = getAuthHeaders(credentials);

        try {
            const res = await fetch('/api/zones', { headers });
            const data = await res.json();
            if (res.ok) {
                const sortedZones = (data.result || []).sort((a, b) =>
                    new Date(b.modified_on) - new Date(a.modified_on)
                );
                setZones(sortedZones);

                // Auto-select logic:
                // 1. If we have a currently selected zone, try to keep it (update with new data)
                // 2. If no selection or current one is gone, select the first one
                if (sortedZones.length > 0) {
                    if (selectedZone) {
                        const stillExists = sortedZones.find(z => z.id === selectedZone.id);
                        if (stillExists) {
                            setSelectedZone(stillExists);
                        } else {
                            setSelectedZone(sortedZones[0]);
                        }
                    } else {
                        setSelectedZone(sortedZones[0]);
                    }
                } else {
                    setSelectedZone(null);
                }
            }
        } catch (err) { }
        setLoading(false);
    };



    useEffect(() => {
        const saved = localStorage.getItem('auth_session') || sessionStorage.getItem('auth_session');
        if (saved) {
            try {
                const credentials = JSON.parse(saved);
                setAuth(credentials);
                fetchZones(credentials);
            } catch (e) {
                localStorage.removeItem('auth_session');
                sessionStorage.removeItem('auth_session');
            }
        }
    }, []);

    const handleLogin = (credentials) => {
        setAuth(credentials);
        if (credentials.remember) {
            localStorage.setItem('auth_session', JSON.stringify(credentials));
        } else {
            // Always use sessionStorage to at least survive refresh within the session
            sessionStorage.setItem('auth_session', JSON.stringify(credentials));
        }
        fetchZones(credentials);
    };

    const handleLogout = () => {
        setAuth(null);
        setZones([]);
        setSelectedZone(null);
        localStorage.removeItem('auth_session');
        sessionStorage.removeItem('auth_session');
    };

    if (!auth) {
        return <Login onLogin={handleLogin} t={t} lang={lang} onLangChange={changeLang} />;
    }

    return (
        <div className="fade-in">
            {toast && (
                <div key={toast.id} style={{
                    position: 'fixed',
                    top: '24px',
                    left: '50%',
                    transform: 'translateX(-50%)',
                    zIndex: 9999,
                    background: toast.type === 'success' ? '#fff' : '#fff5f5',
                    color: toast.type === 'success' ? '#1a202c' : '#c53030',
                    padding: '10px 16px',
                    borderRadius: '12px',
                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    border: toast.type === 'success' ? '1px solid #e2e8f0' : '1px solid #feb2b2',
                    animation: 'fadeDown 0.3s ease-out'
                }}>
                    <style>{`
                        @keyframes fadeDown {
                            from { opacity: 0; transform: translate(-50%, -20px); }
                            to { opacity: 1; transform: translate(-50%, 0); }
                        }
                    `}</style>
                    {toast.type === 'success' ? <CheckCircle size={18} color="var(--success)" /> : <AlertCircle size={18} color="var(--error)" />}
                    <span style={{ fontSize: '0.875rem', fontWeight: '600', whiteSpace: 'nowrap' }}>{toast.message}</span>
                    <button onClick={() => setToast(null)} style={{ border: 'none', background: 'transparent', cursor: 'pointer', padding: '4px', display: 'flex', marginLeft: '4px' }}>
                        <X size={14} color="var(--text-muted)" />
                    </button>
                </div>
            )}
            <header>
                <div className="logo" onClick={() => window.location.reload()} style={{ cursor: 'pointer' }}>
                    <Zap size={22} color="var(--primary)" />
                    DNS <span>Manager</span>
                </div>

                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <button
                        onClick={toggleLang}
                        style={{ border: 'none', background: 'transparent', padding: '8px', cursor: 'pointer', display: 'flex', color: 'var(--text-muted)', borderRadius: '8px', transition: 'all 0.2s' }}
                        onMouseEnter={(e) => {
                            e.currentTarget.style.background = 'rgba(0,0,0,0.05)';
                            e.currentTarget.style.color = 'var(--primary)';
                        }}
                        onMouseLeave={(e) => {
                            e.currentTarget.style.background = 'transparent';
                            e.currentTarget.style.color = 'var(--text-muted)';
                        }}
                        title={lang === 'zh' ? 'English' : '中文'}
                    >
                        <Languages size={18} />
                    </button>

                    <div style={{ height: '16px', width: '1px', background: 'var(--border)' }}></div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: '500' }}>
                        <Server size={14} />
                        {auth.mode === 'server' ? t('managed') : t('clientOnly')}
                    </div>

                    <div style={{ height: '16px', width: '1px', background: 'var(--border)' }}></div>


                    <div style={{ position: 'relative' }} ref={accountSelectorRef}>
                        <button
                            onClick={() => setShowAccountSelector(!showAccountSelector)}
                            style={{ border: 'none', background: 'transparent', padding: '8px', cursor: 'pointer', display: 'flex', color: 'var(--text-muted)', borderRadius: '8px', transition: 'background 0.2s' }}
                            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,0,0,0.05)'}
                            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                            title={t('switchAccount')}
                        >
                            <User size={20} />
                        </button>
                        {showAccountSelector && (
                            <div className="glass-card fade-in" style={{
                                position: 'absolute',
                                top: '120%',
                                right: 0,
                                width: '200px',
                                padding: '0.25rem',
                                zIndex: 100,
                                maxHeight: '300px',
                                overflowY: 'auto'
                            }}>
                                {auth.mode === 'server' && auth.accounts && auth.accounts.length > 1 && (
                                    <>
                                        {auth.accounts.map(acc => (
                                            <div
                                                key={acc.id}
                                                onClick={() => {
                                                    const newAuth = { ...auth, currentAccountIndex: acc.id };
                                                    setAuth(newAuth);
                                                    setSelectedZone(null);
                                                    setZones([]);
                                                    if (newAuth.remember) {
                                                        localStorage.setItem('auth_session', JSON.stringify(newAuth));
                                                    } else {
                                                        sessionStorage.setItem('auth_session', JSON.stringify(newAuth));
                                                    }
                                                    setShowAccountSelector(false);
                                                    fetchZones(newAuth);
                                                }}
                                                style={{
                                                    padding: '0.5rem 0.75rem',
                                                    cursor: 'pointer',
                                                    borderRadius: '6px',
                                                    fontSize: '0.875rem',
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    gap: '8px',
                                                    color: (auth.currentAccountIndex || 0) === acc.id ? 'var(--primary)' : 'var(--text-main)',
                                                    background: (auth.currentAccountIndex || 0) === acc.id ? '#fff7ed' : 'transparent',
                                                    fontWeight: (auth.currentAccountIndex || 0) === acc.id ? 600 : 400
                                                }}
                                                onMouseEnter={e => { if ((auth.currentAccountIndex || 0) !== acc.id) e.currentTarget.style.background = '#f9fafb'; }}
                                                onMouseLeave={e => { if ((auth.currentAccountIndex || 0) !== acc.id) e.currentTarget.style.background = 'transparent'; }}
                                            >
                                                <User size={14} />
                                                {acc.name === 'Default Account' ? (lang === 'zh' ? '默认账户' : 'Default Account') : ((lang === 'zh' ? '账户 ' : 'Account ') + acc.id)}
                                                {(auth.currentAccountIndex || 0) === acc.id && <CheckCircle size={14} style={{ marginLeft: 'auto' }} />}
                                            </div>
                                        ))}
                                        <div style={{ height: '1px', background: 'var(--border)', margin: '0.25rem 0' }}></div>
                                    </>
                                )}

                                <div
                                    onClick={handleLogout}
                                    style={{
                                        padding: '0.5rem 0.75rem',
                                        cursor: 'pointer',
                                        borderRadius: '6px',
                                        fontSize: '0.875rem',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '8px',
                                        color: 'var(--error)',
                                    }}
                                    onMouseEnter={e => e.currentTarget.style.background = '#fef2f2'}
                                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                                >
                                    <LogOut size={14} />
                                    {t('logout')}
                                </div>
                            </div>
                        )}
                    </div>
                </div>

            </header>

            <main style={{ paddingBottom: '3rem' }}>
                {selectedZone ? (
                    <ZoneDetail
                        zone={selectedZone}
                        zones={zones}
                        onSwitchZone={setSelectedZone}
                        onRefreshZones={() => fetchZones(auth)}
                        zonesLoading={loading}
                        auth={auth}
                        onBack={() => { }}
                        t={t}
                        showToast={showToast}
                    />
                ) : (
                    <div className="container" style={{ textAlign: 'center', marginTop: '4rem', color: 'var(--text-muted)' }}>
                        {loading ? (
                            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
                                <RefreshCw className="spin" size={32} style={{ color: 'var(--primary)' }} />
                                <p>{t('statusInitializing')}</p>
                            </div>
                        ) : (
                            <p>{t('noZonesFound') || 'No domains found.'}</p>
                        )}
                    </div>
                )}
            </main>
        </div >
    );
};

export default App;
