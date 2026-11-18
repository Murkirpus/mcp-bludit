<?php
/**
 * mcp-bludit.php — MCP-сервер, работающий ВНУТРИ ядра Bludit 3.22.
 *
 * Файл кладётся в корень Bludit (рядом с index.php). Он загружает ядро так же,
 * как index.php (bl-kernel/boot/init.php + плагины) и выполняет все действия
 * штатными функциями движка: createPage(), editPage(), deletePage(),
 * createCategory(), editUser(), editSettings(), activatePlugin(), activateTheme(),
 * transformImage() и т.д. Поэтому срабатывают хуки плагинов (afterPageCreate,
 * afterPageModify, afterPageDelete), пересчитываются индексы тегов/категорий,
 * пишется журнал syslog, проверяются роли — как при работе из админки.
 *
 * Авторизация: токен пользователя Bludit (Админка → Пользователи → профиль →
 * «Токен аутентификации»). Передаётся как:
 *   - заголовок  Authorization: Bearer <токен>
 *   - или заголовок X-Bludit-Token: <токен>
 *   - или параметр URL  ?token=<токен>  (удобно для коннекторов Claude)
 * Действия выполняются от имени владельца токена, с его ролью
 * (admin / editor / author) — точно так же, как в админке.
 *
 * Протокол: MCP Streamable HTTP (JSON-RPC 2.0 через POST, ответ application/json).
 */

// ============================================================================
// НАСТРОЙКИ
// ============================================================================

define('MCP_SERVER_NAME',        'bludit-core');
define('MCP_SERVER_VERSION',     '1.1.0');
define('MCP_ALLOW_QUERY_TOKEN',  false);             // true — разрешить ?token=... в URL (токен попадёт в логи)
define('MCP_ALLOWED_IPS',        '');                // через запятую; пусто = любые IP
define('MCP_MAX_DOWNLOAD_BYTES', 25 * 1024 * 1024);  // лимит скачивания файла по URL
define('MCP_DOWNLOAD_TIMEOUT',   30);                // секунд

// ============================================================================
// HTTP-уровень (до загрузки ядра)
// ============================================================================

$mcpMethod = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if ($mcpMethod === 'OPTIONS') {
	header('Access-Control-Allow-Origin: *');
	header('Access-Control-Allow-Methods: POST, OPTIONS');
	header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Bludit-Token, Mcp-Session-Id, Mcp-Protocol-Version');
	http_response_code(204);
	exit;
}

if ($mcpMethod !== 'POST') {
	header('Allow: POST, OPTIONS');
	header('Content-Type: application/json; charset=utf-8');
	http_response_code(405);
	echo json_encode(array('error' => 'Use POST (MCP Streamable HTTP).'));
	exit;
}

if (MCP_ALLOWED_IPS !== '') {
	$mcpIps = array_map('trim', explode(',', MCP_ALLOWED_IPS));
	$mcpRemote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
	if (!in_array($mcpRemote, $mcpIps, true)) {
		header('Content-Type: application/json; charset=utf-8');
		http_response_code(403);
		echo json_encode(array('error' => 'Forbidden'));
		exit;
	}
}

if (!file_exists(__DIR__ . '/bl-content/databases/site.php')) {
	header('Content-Type: application/json; charset=utf-8');
	http_response_code(500);
	echo json_encode(array('error' => 'Bludit is not installed in this directory.'));
	exit;
}

// Токен
$mcpToken = '';
$mcpAuthHeader = '';
if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
	$mcpAuthHeader = $_SERVER['HTTP_AUTHORIZATION'];
} elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
	$mcpAuthHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
} elseif (function_exists('getallheaders')) {
	foreach (getallheaders() as $h => $v) {
		if (strtolower($h) === 'authorization') { $mcpAuthHeader = $v; }
	}
}
if (preg_match('/^\s*Bearer\s+(\S+)\s*$/i', $mcpAuthHeader, $m)) {
	$mcpToken = $m[1];
} elseif (!empty($_SERVER['HTTP_X_BLUDIT_TOKEN'])) {
	$mcpToken = trim($_SERVER['HTTP_X_BLUDIT_TOKEN']);
} elseif (MCP_ALLOW_QUERY_TOKEN && !empty($_GET['token'])) {
	$mcpToken = trim((string) $_GET['token']);
}

// Тело запроса
$mcpRawBody = file_get_contents('php://input');

// ============================================================================
// ЗАГРУЗКА ЯДРА BLUDIT (на верхнем уровне — переменные ядра должны быть глобальными)
// ============================================================================

// Всё, что ядро или плагины выведут через echo, перехватываем, чтобы не сломать JSON
ob_start();

define('BLUDIT', true);
define('DS', DIRECTORY_SEPARATOR);
define('PATH_ROOT', __DIR__ . DS);
define('PATH_BOOT', PATH_ROOT . 'bl-kernel' . DS . 'boot' . DS);

require PATH_BOOT . 'init.php';

// Сессия без cookie и без файла сессии: только массив в памяти на время запроса
$_SESSION = array();

/**
 * Login без session_start(): методы username()/role() берутся из $_SESSION
 * через Session::get(), как и в оригинальном классе.
 */
class McpLogin extends Login
{
	public function __construct()
	{
		$this->users = $GLOBALS['users'];
		$this->site  = $GLOBALS['site'];
	}
}

// Плагины (тот же файл правил, что использует админка)
include PATH_RULES . '60.plugins.php';

ob_end_clean();

// ============================================================================
// JSON-RPC вывод
// ============================================================================

function mcp_send($payload, $httpCode = 200)
{
	while (ob_get_level() > 0) {
		ob_end_clean();
	}
	http_response_code($httpCode);
	header('Content-Type: application/json; charset=utf-8');
	if ($payload !== null) {
		echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
	}
	exit;
}

function mcp_rpc_error($id, $code, $message, $httpCode = 200)
{
	mcp_send(array('jsonrpc' => '2.0', 'id' => $id, 'error' => array('code' => $code, 'message' => $message)), $httpCode);
}

// ============================================================================
// АВТОРИЗАЦИЯ ЧЕРЕЗ ПОЛЬЗОВАТЕЛЕЙ BLUDIT
// ============================================================================

$mcpUsername = false;
if ($mcpToken !== '' && strlen($mcpToken) >= 16) {
	foreach ($users->db as $uName => $uFields) {
		if (!empty($uFields['tokenAuth']) && hash_equals((string) $uFields['tokenAuth'], $mcpToken)) {
			$mcpUsername = $uName;
			break;
		}
	}
}

if ($mcpUsername === false) {
	header('WWW-Authenticate: Bearer realm="bludit-mcp"');
	mcp_send(array('jsonrpc' => '2.0', 'id' => null, 'error' => array('code' => -32001, 'message' => 'Unauthorized: invalid or missing Bludit user token.')), 401);
}

$mcpUserRow = $users->getUserDB($mcpUsername);
if ($mcpUserRow === false || $mcpUserRow['password'] === '!') {
	mcp_send(array('jsonrpc' => '2.0', 'id' => null, 'error' => array('code' => -32001, 'message' => 'Unauthorized: user is disabled.')), 401);
}

// «Входим» в Bludit от имени пользователя — функции ядра читают Session/$login
Session::set('username', $mcpUsername);
Session::set('role', $mcpUserRow['role']);
$login = new McpLogin();

// Как в правилах 69.pages.php: публикуем отложенные страницы, у которых настало время
ob_start();
if ($pages->scheduler()) {
	Theme::plugins('afterPageCreate');
	reindexTags();
	reindexCategories();
}
ob_end_clean();

// ============================================================================
// ВСПОМОГАТЕЛЬНОЕ
// ============================================================================

class McpToolError extends Exception {}

function mcp_fail($message)
{
	throw new McpToolError($message);
}

function mcp_role()
{
	return Session::get('role');
}

function mcp_user()
{
	return Session::get('username');
}

function mcp_require_role($roles)
{
	if (!in_array(mcp_role(), $roles, true)) {
		mcp_fail('Недостаточно прав: нужна роль ' . implode(' или ', $roles) . ', у вас — ' . mcp_role() . '.');
	}
}

// Сообщение, которое ядро положило в Alert (если положило)
function mcp_alert_message($fallback)
{
	$msg = Session::get('alert');
	Session::remove('alert');
	if (!empty($msg)) {
		return $fallback . ' Bludit: ' . $msg;
	}
	return $fallback;
}

function mcp_clear_alert()
{
	Session::remove('alert');
}

function mcp_arg($args, $name, $default = null)
{
	return (is_array($args) && array_key_exists($name, $args)) ? $args[$name] : $default;
}

function mcp_bool01($v)
{
	if (is_string($v)) {
		$v = strtolower(trim($v));
		return in_array($v, array('1', 'true', 'yes', 'on'), true) ? '1' : '0';
	}
	return $v ? '1' : '0';
}

function mcp_date($v)
{
	$v = trim((string) $v);
	if ($v === '') {
		return '';
	}
	if (Valid::date($v, DB_DATE_FORMAT)) {
		return $v;
	}
	$ts = strtotime($v);
	if ($ts === false) {
		mcp_fail('Не удалось разобрать дату: ' . $v . ' (ожидается формат ГГГГ-ММ-ДД ЧЧ:ММ:СС).');
	}
	return date(DB_DATE_FORMAT, $ts);
}

function mcp_tags_to_string($tags)
{
	if (is_array($tags)) {
		$tags = array_map('trim', $tags);
		$tags = array_filter($tags, 'strlen');
		return implode(',', $tags);
	}
	return trim((string) $tags);
}

function mcp_page($key)
{
	global $pages;
	$key = trim((string) $key, " /");
	if ($key === '' || !$pages->exists($key)) {
		mcp_fail('Страница не найдена: ' . $key);
	}
	try {
		return new Page($key);
	} catch (Exception $e) {
		mcp_fail('Не удалось загрузить страницу: ' . $key);
	}
}

// Поиск страницы по key или по uuid
function mcp_resolve_page_key($args)
{
	global $pages;
	$key = mcp_arg($args, 'key', '');
	if ($key === '' || $key === null) {
		$uuid = mcp_arg($args, 'uuid', '');
		if ($uuid !== '') {
			$found = $pages->getByUUID($uuid);
			if ($found) {
				return $found;
			}
			mcp_fail('Страница с uuid ' . $uuid . ' не найдена.');
		}
		mcp_fail('Укажите key (или uuid) страницы.');
	}
	return trim((string) $key, " /");
}

// Автор может работать только со своими страницами (как в edit-content.php)
function mcp_check_page_owner($key)
{
	global $pages, $syslog;
	if (mcp_role() === 'author') {
		$row = $pages->getPageDB($key);
		if ($row === false || $row['username'] !== mcp_user()) {
			$syslog->add(array('dictionaryKey' => 'access-denied', 'notes' => mcp_user()));
			mcp_fail('Автор может изменять только свои страницы.');
		}
	}
}

function mcp_page_data($key, $withContent = false, $format = 'raw')
{
	global $pages, $categories;
	$p   = mcp_page($key);
	$row = $pages->getPageDB($key);

	$custom = array();
	if (!empty($row['custom']) && is_array($row['custom'])) {
		foreach ($row['custom'] as $f => $v) {
			if (is_string($f) && is_array($v) && array_key_exists('value', $v)) {
				$custom[$f] = $v['value'];
			}
		}
	}

	$categoryKey = $row['category'];
	$data = array(
		'key'           => $key,
		'title'         => $p->title(),
		'slug'          => $p->slug(),
		'type'          => $p->type(),
		'parent'        => $p->parentKey() ? $p->parentKey() : '',
		'children'      => $p->childrenKeys(),
		'date'          => $p->dateRaw(),
		'dateModified'  => $row['dateModified'],
		'username'      => $p->username(),
		'category'      => $categoryKey,
		'categoryName'  => ($categoryKey !== '' && $categories->exists($categoryKey)) ? $categories->getName($categoryKey) : '',
		'tags'          => $row['tags'],
		'description'   => $p->description(),
		'coverImage'    => $p->coverImage(false) ? $p->coverImage(false) : '',
		'coverImageUrl' => $p->coverImage(true) ? $p->coverImage(true) : '',
		'template'      => $row['template'],
		'position'      => $row['position'],
		'allowComments' => (bool) $row['allowComments'],
		'noindex'       => (bool) $row['noindex'],
		'nofollow'      => (bool) $row['nofollow'],
		'noarchive'     => (bool) $row['noarchive'],
		'uuid'          => $p->uuid(),
		'custom'        => $custom,
		'permalink'     => $p->permalink(true),
	);

	if ($withContent) {
		if ($format === 'raw' || $format === 'both') {
			$data['content'] = $p->contentRaw(false);
		}
		if ($format === 'html' || $format === 'both') {
			$data['contentHtml'] = $p->content(false);
		}
	}
	return $data;
}

// Проверка и подготовка полей страницы из аргументов инструмента
function mcp_page_fields($args, $currentKey = false)
{
	global $pages, $categories, $site, $users;

	$out = array();

	foreach (array('title', 'description', 'template') as $f) {
		if (array_key_exists($f, $args)) {
			$out[$f] = (string) $args[$f];
		}
	}

	if (array_key_exists('content', $args)) {
		$out['content'] = (string) $args['content'];
	}

	if (array_key_exists('slug', $args) && $args['slug'] !== '') {
		$out['slug'] = (string) $args['slug'];
	}

	if (array_key_exists('type', $args)) {
		$allowed = array('published', 'static', 'sticky', 'draft');
		if (!in_array($args['type'], $allowed, true)) {
			mcp_fail('Недопустимый type. Допустимо: ' . implode(', ', $allowed) . ' (scheduled выставляется сам при дате в будущем).');
		}
		$out['type'] = $args['type'];
	}

	if (array_key_exists('category', $args)) {
		$cat = (string) $args['category'];
		if ($cat !== '' && !$categories->exists($cat)) {
			mcp_fail('Категория не найдена: ' . $cat . '. Существующие: ' . implode(', ', $categories->keys()));
		}
		$out['category'] = $cat;
	}

	if (array_key_exists('tags', $args)) {
		$out['tags'] = mcp_tags_to_string($args['tags']);
	}

	if (array_key_exists('date', $args) && $args['date'] !== '') {
		$out['date'] = mcp_date($args['date']);
	}

	if (array_key_exists('position', $args)) {
		$out['position'] = (int) $args['position'];
	}

	foreach (array('allowComments', 'noindex', 'nofollow', 'noarchive') as $f) {
		if (array_key_exists($f, $args)) {
			$out[$f] = mcp_bool01($args[$f]);
		}
	}

	if (array_key_exists('coverImage', $args)) {
		$out['coverImage'] = (string) $args['coverImage'];
	}

	if (array_key_exists('parent', $args)) {
		$parent = trim((string) $args['parent'], " /");
		if ($parent !== '') {
			if (!$pages->exists($parent)) {
				mcp_fail('Родительская страница не найдена: ' . $parent);
			}
			if (strpos($parent, '/') !== false) {
				mcp_fail('Bludit поддерживает только один уровень вложенности: родитель не может сам быть дочерней страницей.');
			}
			if ($currentKey !== false && $parent === $currentKey) {
				mcp_fail('Страница не может быть родителем самой себя.');
			}
		}
		$out['parent'] = $parent;
	}

	if (array_key_exists('username', $args)) {
		if (!in_array(mcp_role(), array('admin', 'editor'), true)) {
			mcp_fail('Менять автора страницы может только admin или editor.');
		}
		if (!$users->exists($args['username'])) {
			mcp_fail('Пользователь не найден: ' . $args['username']);
		}
		$out['username'] = $args['username'];
	}

	// Пользовательские поля.
	// Ядро (Pages::add/edit) портит поле custom, если его не передать, поэтому
	// при объявленных полях всегда передаём полный набор: текущие значения
	// (или значения по умолчанию) + то, что пришло в аргументах.
	$defined = $site->customFields();
	if (!is_array($defined)) {
		$defined = array();
	}
	$custom = array_key_exists('custom', $args) ? $args['custom'] : array();
	if (!is_array($custom)) {
		mcp_fail('custom должен быть объектом {"поле": "значение"}.');
	}
	if (!empty($custom) && empty($defined)) {
		mcp_fail('В настройках сайта не объявлено ни одного пользовательского поля (customFields).');
	}
	if (!empty($defined)) {
		$final = array();
		$row = $currentKey !== false ? $pages->getPageDB($currentKey) : false;
		foreach ($defined as $f => $def) {
			$val = isset($def['default']) ? $def['default'] : '';
			if ($row && isset($row['custom'][$f]) && is_array($row['custom'][$f]) && array_key_exists('value', $row['custom'][$f])) {
				$val = $row['custom'][$f]['value'];
			}
			$final[$f] = $val;
		}
		foreach ($custom as $f => $v) {
			if (!isset($defined[$f])) {
				mcp_fail('Пользовательское поле «' . $f . '» не объявлено в настройках сайта. Объявленные: ' . implode(', ', array_keys($defined)));
			}
			$final[$f] = $v;
		}
		foreach ($final as $f => $v) {
			if (isset($defined[$f]['type']) && $defined[$f]['type'] === 'bool') {
				$final[$f] = mcp_bool01($v);
			} else {
				$final[$f] = is_scalar($v) || $v === null ? (string) $v : json_encode($v, JSON_UNESCAPED_UNICODE);
			}
		}
		$out['custom'] = $final;
	}

	return $out;
}

// editPage() с полным набором полей, как его отправляет форма админки:
// сохраняет родителя и пользовательские поля, которые иначе ядро сбрасывает
function mcp_core_edit($key, $changes)
{
	$args = mcp_page_fields($changes, $key);
	if (!array_key_exists('parent', $args)) {
		$pos = strpos($key, '/');
		$args['parent'] = $pos !== false ? substr($key, 0, $pos) : '';
	}
	if (isset($args['content']) && $args['content'] === '') {
		unset($args['content']);
	}
	$args['key'] = $key;
	mcp_clear_alert();
	ob_start();
	$newKey = editPage($args);
	ob_end_clean();
	if ($newKey === false) {
		mcp_fail(mcp_alert_message('editPage() вернула ошибку для ' . $key . '.'));
	}
	return $newKey;
}

// Скачать файл по URL или раскодировать base64 во временный файл Bludit
function mcp_fetch_to_tmp($args, $defaultName = 'file')
{
	$url    = mcp_arg($args, 'url', '');
	$b64    = mcp_arg($args, 'base64', '');
	$name   = (string) mcp_arg($args, 'filename', '');

	if ($url === '' && $b64 === '') {
		mcp_fail('Передайте url или base64.');
	}

	if (!Filesystem::directoryExists(PATH_TMP)) {
		Filesystem::mkdir(PATH_TMP, true);
	}

	if ($url !== '') {
		if (!preg_match('#^https?://#i', $url)) {
			mcp_fail('Поддерживаются только http(s)-ссылки.');
		}
		$host = parse_url($url, PHP_URL_HOST);
		$ip = gethostbyname($host);
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
			mcp_fail('Адрес ссылки указывает на локальную или служебную сеть — скачивание запрещено.');
		}
		$data = mcp_http_get($url);
		if ($name === '') {
			$name = basename(parse_url($url, PHP_URL_PATH));
		}
	} else {
		if (strpos($b64, 'base64,') !== false) {
			$b64 = substr($b64, strpos($b64, 'base64,') + 7);
		}
		$data = base64_decode($b64, true);
		if ($data === false) {
			mcp_fail('Некорректный base64.');
		}
	}

	if (strlen($data) === 0) {
		mcp_fail('Получен пустой файл.');
	}
	if (strlen($data) > MCP_MAX_DOWNLOAD_BYTES) {
		mcp_fail('Файл больше лимита ' . MCP_MAX_DOWNLOAD_BYTES . ' байт.');
	}

	$name = urldecode($name);
	if ($name === '' || strpos($name, '.') === false) {
		$ext = mcp_guess_ext($data);
		$name = ($name === '' ? $defaultName : $name) . ($ext ? '.' . $ext : '');
	}

	// Та же очистка имени, что в ajax/upload-images.php
	$ext  = Text::lowercase(Filesystem::extension($name));
	$base = pathinfo($name, PATHINFO_FILENAME);
	$base = Text::removeSpecialCharacters($base, '-');
	$base = Text::removeQuotes($base);
	$base = Text::removeSpaces($base, '-');
	$base = trim($base, '.-');
	if ($base === '') {
		$base = $defaultName;
	}
	$name = $base . '.' . $ext;

	if (strpos($name, '.') === 0 || Text::stringContains($name, DS, false) || Text::stringContains($name, '/', false)) {
		mcp_fail('Недопустимое имя файла.');
	}

	$tmp = PATH_TMP . 'mcp-' . uniqid() . '-' . $name;
	if (file_put_contents($tmp, $data) === false) {
		mcp_fail('Не удалось записать временный файл в ' . PATH_TMP);
	}
	return array('tmp' => $tmp, 'name' => $name, 'ext' => $ext, 'size' => strlen($data));
}

function mcp_http_get($url)
{
	if (function_exists('curl_init')) {
		$ch = curl_init($url);
		$buf = '';
		curl_setopt_array($ch, array(
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_MAXREDIRS      => 5,
			CURLOPT_TIMEOUT        => MCP_DOWNLOAD_TIMEOUT,
			CURLOPT_CONNECTTIMEOUT => 10,
			CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; BluditMCP/' . MCP_SERVER_VERSION . ')',
			CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
			CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
			CURLOPT_WRITEFUNCTION  => function ($ch, $chunk) use (&$buf) {
				$buf .= $chunk;
				if (strlen($buf) > MCP_MAX_DOWNLOAD_BYTES) {
					return 0;
				}
				return strlen($chunk);
			},
		));
		curl_exec($ch);
		$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$err  = curl_error($ch);
		curl_close($ch);
		if (strlen($buf) > MCP_MAX_DOWNLOAD_BYTES) {
			mcp_fail('Файл больше лимита ' . MCP_MAX_DOWNLOAD_BYTES . ' байт.');
		}
		if ($code < 200 || $code >= 300) {
			mcp_fail('Не удалось скачать файл (HTTP ' . $code . ($err ? ', ' . $err : '') . ').');
		}
		return $buf;
	}
	$ctx = stream_context_create(array('http' => array('timeout' => MCP_DOWNLOAD_TIMEOUT, 'follow_location' => 1, 'user_agent' => 'BluditMCP')));
	$data = @file_get_contents($url, false, $ctx, 0, MCP_MAX_DOWNLOAD_BYTES + 1);
	if ($data === false) {
		mcp_fail('Не удалось скачать файл по ссылке.');
	}
	return $data;
}

function mcp_guess_ext($data)
{
	if (function_exists('finfo_open')) {
		$f = finfo_open(FILEINFO_MIME_TYPE);
		$mime = finfo_buffer($f, $data);
		finfo_close($f);
		$map = array(
			'image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif', 'image/webp' => 'webp',
			'image/svg+xml' => 'svg', 'application/pdf' => 'pdf', 'text/plain' => 'txt', 'application/zip' => 'zip',
			'audio/mpeg' => 'mp3', 'video/mp4' => 'mp4', 'application/json' => 'json',
		);
		if (isset($map[$mime])) {
			return $map[$mime];
		}
	}
	return '';
}

// Каталоги загрузки картинок — та же логика, что в ajax/upload-images.php
function mcp_image_dirs($pageKey)
{
	global $pages;
	$uuid = false;
	if ($pageKey !== '' && $pageKey !== null) {
		$uuid = $pages->getUUID($pageKey);
		if (!$uuid) {
			mcp_fail('Страница не найдена: ' . $pageKey);
		}
	}
	if ($uuid && IMAGE_RESTRICT) {
		$dir = PATH_UPLOADS_PAGES . $uuid . DS;
		return array(
			'uuid' => $uuid,
			'dir' => $dir,
			'thumbs' => $dir . 'thumbnails' . DS,
			'url' => DOMAIN_UPLOADS_PAGES . $uuid . '/',
			'thumbsUrl' => DOMAIN_UPLOADS_PAGES . $uuid . '/thumbnails/',
		);
	}
	return array(
		'uuid' => $uuid,
		'dir' => PATH_UPLOADS,
		'thumbs' => PATH_UPLOADS_THUMBNAILS,
		'url' => DOMAIN_UPLOADS,
		'thumbsUrl' => DOMAIN_UPLOADS_THUMBNAILS,
	);
}

function mcp_plugin_info($className, $plugin)
{
	$settings = array();
	if ($plugin->installed() && is_array($plugin->db)) {
		foreach ($plugin->dbFields as $f => $default) {
			$settings[$f] = array_key_exists($f, $plugin->db) ? $plugin->db[$f] : $default;
		}
	}
	return array(
		'className'    => $className,
		'directory'    => $plugin->directoryName(),
		'name'         => $plugin->name(),
		'description'  => $plugin->description(),
		'version'      => $plugin->version(),
		'author'       => $plugin->author(),
		'type'         => $plugin->type(),
		'active'       => $plugin->installed(),
		'position'     => $plugin->installed() ? $plugin->position() : null,
		'compatible'   => $plugin->isCompatible(),
		'configurable' => method_exists($plugin, 'form'),
		'settingsSchema' => $plugin->dbFields,
		'settings'     => $settings,
	);
}

function mcp_find_plugin($name)
{
	global $plugins;
	if (isset($plugins['all'][$name])) {
		return array($name, $plugins['all'][$name]);
	}
	foreach ($plugins['all'] as $cls => $p) {
		if (strcasecmp($cls, $name) === 0 || strcasecmp($p->directoryName(), $name) === 0) {
			return array($cls, $p);
		}
	}
	mcp_fail('Плагин не найден: ' . $name . '. Посмотрите список через bludit_plugins_list.');
}

// ============================================================================
// ИНСТРУМЕНТЫ
// ============================================================================

$S_PAGE_FIELDS = array(
	'title'         => array('type' => 'string', 'description' => 'Заголовок'),
	'content'       => array('type' => 'string', 'description' => 'Содержимое: Markdown или HTML (как в редакторе сайта)'),
	'slug'          => array('type' => 'string', 'description' => 'Friendly URL (slug). При смене меняется key страницы'),
	'description'   => array('type' => 'string', 'description' => 'Краткое описание (meta description)'),
	'tags'          => array('description' => 'Теги: массив строк или строка через запятую', 'anyOf' => array(array('type' => 'array', 'items' => array('type' => 'string')), array('type' => 'string'))),
	'category'      => array('type' => 'string', 'description' => 'Ключ категории ("" — без категории)'),
	'type'          => array('type' => 'string', 'enum' => array('published', 'static', 'sticky', 'draft'), 'description' => 'Тип/статус. Дата в будущем + published = отложенная публикация (scheduled)'),
	'date'          => array('type' => 'string', 'description' => 'Дата публикации, ГГГГ-ММ-ДД ЧЧ:ММ:СС (часовой пояс сайта)'),
	'parent'        => array('type' => 'string', 'description' => 'Ключ родительской страницы ("" — убрать родителя)'),
	'coverImage'    => array('type' => 'string', 'description' => 'Обложка: имя файла из загрузок страницы или полный URL'),
	'template'      => array('type' => 'string', 'description' => 'Шаблон темы'),
	'position'      => array('type' => 'integer', 'description' => 'Позиция (для сортировки по позиции)'),
	'allowComments' => array('type' => 'boolean'),
	'noindex'       => array('type' => 'boolean'),
	'nofollow'      => array('type' => 'boolean'),
	'noarchive'     => array('type' => 'boolean'),
	'custom'        => array('type' => 'object', 'description' => 'Пользовательские поля {"имя": значение} — должны быть объявлены в настройках (customFields)'),
);

$TOOLS = array();

// ---------------------------------------------------------------- Сайт
$TOOLS['bludit_info'] = array(
	'description' => 'Сводка о сайте Bludit: версия, текущий пользователь и его роль, тема, активные плагины, счётчики страниц, категории, пользовательские поля, режим загрузки картинок. Начинайте с этого инструмента.',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $site, $pages, $categories, $tags, $users, $pluginsInstalled;
		$counts = array();
		foreach (array('published', 'static', 'sticky', 'draft', 'scheduled', 'autosave') as $t) {
			$counts[$t] = 0;
		}
		foreach ($pages->db as $row) {
			if (isset($counts[$row['type']])) {
				$counts[$row['type']]++;
			}
		}
		$active = array();
		foreach ($pluginsInstalled as $cls => $p) {
			$active[] = $cls;
		}
		return array(
			'bludit'     => array('version' => BLUDIT_VERSION, 'codename' => BLUDIT_CODENAME, 'build' => BLUDIT_BUILD, 'php' => PHP_VERSION),
			'site'       => array('title' => $site->title(), 'url' => DOMAIN_BASE, 'language' => $site->language(), 'timezone' => $site->timezone(), 'theme' => $site->theme(), 'orderBy' => $site->orderBy(), 'markdownParser' => MARKDOWN_PARSER, 'homepage' => $site->homepage(), 'pageNotFound' => $site->pageNotFound()),
			'user'       => array('username' => mcp_user(), 'role' => mcp_role()),
			'pages'      => array('total' => count($pages->db), 'byType' => $counts),
			'categories' => $categories->getKeyNameArray(),
			'tagsCount'  => count($tags->db),
			'usersCount' => count($users->db),
			'customFields' => $site->customFields(),
			'uploads'    => array('imageRestrictToPage' => IMAGE_RESTRICT, 'imageRelativeToAbsolute' => IMAGE_RELATIVE_TO_ABSOLUTE, 'allowedImages' => $GLOBALS['ALLOWED_IMG_EXTENSION'], 'allowedFiles' => $GLOBALS['ALLOWED_FILE_EXTENSIONS']),
			'activePlugins' => $active,
			'serverTime' => Date::current(DB_DATE_FORMAT),
		);
	},
);

$TOOLS['bludit_settings_get'] = array(
	'description' => 'Все настройки сайта (site.php): заголовок, слоган, язык, часовой пояс, URL-фильтры, домашняя страница, соцсети, миниатюры, customFields и т.д.',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $site;
		$data = $site->get();
		$data['customFields'] = $site->customFields();
		return $data;
	},
);

$TOOLS['bludit_settings_edit'] = array(
	'description' => 'Изменить настройки сайта штатной функцией editSettings() (пересортировка при смене orderBy, syslog). Передавайте только меняемые поля в settings — остальные сохраняются. customFields — объект с объявлением полей, например {"subtitle":{"type":"string","label":"Подзаголовок"}}.',
	'schema' => array('type' => 'object', 'required' => array('settings'), 'properties' => array(
		'settings' => array('type' => 'object', 'description' => 'Поля из bludit_settings_get, которые нужно изменить'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $site;
		$changes = mcp_arg($a, 'settings', array());
		if (!is_array($changes) || empty($changes)) {
			mcp_fail('settings пуст.');
		}
		$known = array_keys($site->dbFields);
		$unknown = array_diff(array_keys($changes), $known);
		if (!empty($unknown)) {
			mcp_fail('Неизвестные поля настроек: ' . implode(', ', $unknown));
		}
		if (array_key_exists('theme', $changes)) {
			mcp_fail('Тему меняйте через bludit_theme_activate — там выполняется установка темы и её плагина.');
		}
		// editSettings() ожидает полный набор полей (как форма админки),
		// иначе, например, сбросит homepage. Поэтому дополняем текущими значениями.
		$args = $site->get();
		unset($args['customFields']);
		foreach ($changes as $k => $v) {
			if ($k === 'customFields') {
				$v = is_string($v) ? $v : json_encode($v, JSON_UNESCAPED_UNICODE);
				json_decode($v);
				if (json_last_error() !== JSON_ERROR_NONE) {
					mcp_fail('customFields: некорректный JSON.');
				}
				$args['customFields'] = $v;
				continue;
			}
			if (is_bool($v)) {
				$v = $v ? 'true' : 'false';
			}
			$args[$k] = $v;
		}
		if (isset($args['extremeFriendly']) && is_bool($args['extremeFriendly'])) {
			$args['extremeFriendly'] = $args['extremeFriendly'] ? 'true' : 'false';
		}
		mcp_clear_alert();
		if (!editSettings($args)) {
			mcp_fail(mcp_alert_message('editSettings() вернула ошибку.'));
		}
		$data = $site->get();
		$data['customFields'] = $site->customFields();
		return array('message' => 'Настройки сохранены.', 'changed' => array_keys($changes), 'settings' => $data);
	},
);

$TOOLS['bludit_logo_upload'] = array(
	'description' => 'Загрузить логотип сайта (как ajax/logo-upload.php). Источник: url или base64.',
	'schema' => array('type' => 'object', 'properties' => array(
		'url' => array('type' => 'string'), 'base64' => array('type' => 'string'), 'filename' => array('type' => 'string'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $site;
		$f = mcp_fetch_to_tmp($a, 'logo');
		if (!in_array($f['ext'], $GLOBALS['ALLOWED_IMG_EXTENSION'], true)) {
			@unlink($f['tmp']);
			mcp_fail('Тип файла не поддерживается. Разрешено: ' . implode(', ', $GLOBALS['ALLOWED_IMG_EXTENSION']));
		}
		$mime = Filesystem::mimeType($f['tmp']);
		if ($mime !== false && !in_array($mime, $GLOBALS['ALLOWED_IMG_MIMETYPES'], true)) {
			@unlink($f['tmp']);
			mcp_fail('MIME-тип не поддерживается: ' . $mime);
		}
		$filename = 'logo.' . $f['ext'];
		if (Text::isNotEmpty($site->title())) {
			$t = Text::removeSpecialCharacters($site->title(), '-');
			$t = Text::removeQuotes($t);
			$t = Text::removeSpaces($t, '-');
			$t = trim($t, '-');
			if (Text::isNotEmpty($t)) {
				$filename = $t . '.' . $f['ext'];
			}
		}
		$old = $site->logo(false);
		if ($old) {
			Filesystem::rmfile(PATH_UPLOADS . $old);
		}
		Filesystem::mv($f['tmp'], PATH_UPLOADS . $filename);
		chmod(PATH_UPLOADS . $filename, 0644);
		$site->set(array('logo' => $filename));
		return array('message' => 'Логотип загружен.', 'filename' => $filename, 'url' => DOMAIN_UPLOADS . $filename);
	},
);

$TOOLS['bludit_logo_remove'] = array(
	'description' => 'Удалить логотип сайта (как ajax/logo-remove.php).',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $site;
		$old = $site->logo(false);
		if ($old) {
			Filesystem::rmfile(PATH_UPLOADS . $old);
		}
		$site->set(array('logo' => ''));
		return array('message' => 'Логотип удалён.');
	},
);

// ---------------------------------------------------------------- Страницы
$TOOLS['bludit_pages_list'] = array(
	'description' => 'Список страниц с фильтрами (тип, категория, тег, автор, родитель, поиск по заголовку/тексту) и пагинацией. Порядок — как на сайте (по дате или позиции). Без текста страниц; полный текст — bludit_page_get.',
	'schema' => array('type' => 'object', 'properties' => array(
		'type'     => array('type' => 'string', 'enum' => array('all', 'published', 'static', 'sticky', 'draft', 'scheduled', 'autosave'), 'description' => 'По умолчанию all (без autosave)'),
		'category' => array('type' => 'string', 'description' => 'Ключ категории'),
		'tag'      => array('type' => 'string', 'description' => 'Ключ или название тега'),
		'username' => array('type' => 'string', 'description' => 'Автор'),
		'parent'   => array('type' => 'string', 'description' => 'Ключ родителя — только его дочерние страницы; "/" — только страницы верхнего уровня'),
		'search'   => array('type' => 'string', 'description' => 'Подстрока в заголовке, ключе или тексте (без учёта регистра)'),
		'page'     => array('type' => 'integer', 'minimum' => 1, 'description' => 'Номер страницы выдачи, с 1'),
		'limit'    => array('type' => 'integer', 'minimum' => 1, 'maximum' => 500, 'description' => 'Сколько на страницу (по умолчанию 50)'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$type     = mcp_arg($a, 'type', 'all');
		$category = mcp_arg($a, 'category', null);
		$tag      = mcp_arg($a, 'tag', null);
		$username = mcp_arg($a, 'username', null);
		$parent   = mcp_arg($a, 'parent', null);
		$search   = mcp_arg($a, 'search', null);
		$pageNum  = max(1, (int) mcp_arg($a, 'page', 1));
		$limit    = min(500, max(1, (int) mcp_arg($a, 'limit', 50)));
		$tagKey   = $tag !== null ? Text::cleanUrl($tag) : null;
		$needle   = ($search !== null && $search !== '') ? Text::lowercase($search) : null;

		$matched = array();
		foreach ($pages->db as $key => $row) {
			if ($type === 'all' && $row['type'] === 'autosave') continue;
			if ($type !== 'all' && $row['type'] !== $type) continue;
			if ($category !== null && $row['category'] !== $category) continue;
			if ($username !== null && $row['username'] !== $username) continue;
			if ($tag !== null && !isset($row['tags'][$tagKey]) && !in_array($tag, $row['tags'], true)) continue;
			if ($parent !== null) {
				$pos = strpos($key, '/');
				if ($parent === '/' || $parent === '') {
					if ($pos !== false) continue;
				} else {
					if (strpos($key, rtrim($parent, '/') . '/') !== 0) continue;
				}
			}
			if ($needle !== null) {
				$hay = Text::lowercase($row['title'] . ' ' . $key);
				if (!Text::stringContains($hay, $needle)) {
					$file = PATH_PAGES . $key . DS . FILENAME;
					$body = is_file($file) ? Text::lowercase(file_get_contents($file)) : '';
					if (!Text::stringContains($body, $needle)) continue;
				}
			}
			$matched[] = $key;
		}

		$total = count($matched);
		$slice = array_slice($matched, ($pageNum - 1) * $limit, $limit);
		$items = array();
		foreach ($slice as $key) {
			$row = $pages->db[$key];
			$items[] = array(
				'key' => $key, 'title' => $row['title'], 'type' => $row['type'], 'date' => $row['date'],
				'category' => $row['category'], 'tags' => array_values($row['tags']), 'username' => $row['username'],
				'position' => $row['position'], 'uuid' => $row['uuid'],
			);
		}
		return array('total' => $total, 'page' => $pageNum, 'limit' => $limit, 'pages' => (int) ceil($total / $limit), 'items' => $items);
	},
);

$TOOLS['bludit_page_get'] = array(
	'description' => 'Полные данные страницы по key (или uuid): поля, теги, категория, родитель/дети, пользовательские поля, ссылка и текст.',
	'schema' => array('type' => 'object', 'properties' => array(
		'key'    => array('type' => 'string', 'description' => 'Ключ страницы (slug; у дочерних «родитель/потомок»)'),
		'uuid'   => array('type' => 'string', 'description' => 'Альтернатива key'),
		'format' => array('type' => 'string', 'enum' => array('raw', 'html', 'both', 'none'), 'description' => 'raw — исходник (Markdown/HTML), html — после обработки Markdown, none — без текста. По умолчанию raw'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		$key = mcp_resolve_page_key($a);
		$format = mcp_arg($a, 'format', 'raw');
		return mcp_page_data($key, $format !== 'none', $format);
	},
);

$TOOLS['bludit_page_create'] = array(
	'description' => 'Создать страницу штатной функцией createPage(): срабатывает хук afterPageCreate (sitemap, кеш и др. плагины), пересчитываются теги и категории, пишется syslog. Автор — владелец токена.',
	'schema' => array('type' => 'object', 'required' => array('title'), 'properties' => $S_PAGE_FIELDS),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$args = mcp_page_fields($a, false);
		if (!isset($args['title']) || trim($args['title']) === '') {
			mcp_fail('Нужен title.');
		}
		if (!isset($args['type'])) {
			$args['type'] = 'published';
		}
		mcp_clear_alert();
		ob_start();
		$key = createPage($args);
		ob_end_clean();
		if ($key === false) {
			mcp_fail(mcp_alert_message('createPage() не смогла создать страницу (подробности в журнале PHP).'));
		}
		return array('message' => 'Страница создана.', 'page' => mcp_page_data($key, false));
	},
);

$TOOLS['bludit_page_edit'] = array(
	'description' => 'Изменить страницу штатной функцией editPage() (хук afterPageModify, переиндексация, syslog). Передавайте только меняемые поля. Пустой content не применяется (так устроено ядро). tags заменяет теги целиком; для точечной правки — add_tags / remove_tags.',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array_merge(
		array('key' => array('type' => 'string', 'description' => 'Текущий ключ страницы')),
		$S_PAGE_FIELDS,
		array(
			'username'    => array('type' => 'string', 'description' => 'Сменить автора (admin/editor)'),
			'add_tags'    => array('type' => 'array', 'items' => array('type' => 'string'), 'description' => 'Добавить теги к существующим'),
			'remove_tags' => array('type' => 'array', 'items' => array('type' => 'string'), 'description' => 'Убрать теги (по названию или ключу)'),
		)
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$key = mcp_resolve_page_key($a);
		mcp_page($key);
		mcp_check_page_owner($key);

		$args = mcp_page_fields($a, $key);
		$row  = $pages->getPageDB($key);

		// Теги: добавление/удаление относительно текущих
		if (isset($a['add_tags']) || isset($a['remove_tags'])) {
			$current = isset($args['tags']) ? $pages->generateTags($args['tags']) : $row['tags'];
			foreach ((array) mcp_arg($a, 'add_tags', array()) as $t) {
				$t = trim($t);
				if ($t !== '') {
					$current[Text::cleanUrl($t)] = $t;
				}
			}
			foreach ((array) mcp_arg($a, 'remove_tags', array()) as $t) {
				$tk = Text::cleanUrl($t);
				unset($current[$tk]);
				foreach ($current as $k => $name) {
					if ($name === $t) {
						unset($current[$k]);
					}
				}
			}
			$args['tags'] = implode(',', array_values($current));
		}

		// Ядро при пустом parent переносит дочернюю страницу на верхний уровень,
		// поэтому, если parent не меняют, передаём текущего родителя (как форма админки).
		if (!array_key_exists('parent', $args)) {
			$pos = strpos($key, '/');
			$args['parent'] = $pos !== false ? substr($key, 0, $pos) : '';
		}
		if ($args['parent'] !== '') {
			$children = $pages->getChildren($key);
			if (!empty($children)) {
				mcp_fail('У страницы есть дочерние страницы — сделать её дочерней нельзя (Bludit поддерживает один уровень).');
			}
		}

		if (isset($args['content']) && $args['content'] === '') {
			unset($args['content']);
		}

		$args['key'] = $key;
		mcp_clear_alert();
		ob_start();
		$newKey = editPage($args);
		ob_end_clean();
		if ($newKey === false) {
			mcp_fail(mcp_alert_message('editPage() вернула ошибку.'));
		}
		return array('message' => 'Страница сохранена.', 'oldKey' => $key, 'page' => mcp_page_data($newKey, false));
	},
);

$TOOLS['bludit_page_delete'] = array(
	'description' => 'Удалить страницу штатной функцией deletePage() (хук afterPageDelete, удаление её картинок, переиндексация, syslog). Если есть дочерние страницы — нужен delete_children=true.',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array(
		'key' => array('type' => 'string'),
		'delete_children' => array('type' => 'boolean', 'description' => 'Удалить и дочерние страницы'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$key = mcp_resolve_page_key($a);
		mcp_page($key);
		mcp_check_page_owner($key);
		$children = $pages->getChildren($key);
		$deleted = array();
		if (!empty($children)) {
			if (!mcp_arg($a, 'delete_children', false)) {
				mcp_fail('У страницы есть дочерние: ' . implode(', ', $children) . '. Передайте delete_children=true или сначала перенесите их.');
			}
			foreach ($children as $child) {
				mcp_check_page_owner($child);
			}
			foreach ($children as $child) {
				ob_start();
				$ok = deletePage($child);
				ob_end_clean();
				if ($ok) {
					$deleted[] = $child;
				}
			}
		}
		ob_start();
		$ok = deletePage($key);
		ob_end_clean();
		if (!$ok) {
			mcp_fail('deletePage() вернула ошибку.');
		}
		$deleted[] = $key;
		return array('message' => 'Удалено.', 'deleted' => $deleted);
	},
);

$TOOLS['bludit_page_set_type'] = array(
	'description' => 'Быстро сменить тип страницы (published / sticky / static / draft) — как переключатель в списке контента админки (ajax/change-type.php).',
	'schema' => array('type' => 'object', 'required' => array('key', 'type'), 'properties' => array(
		'key'  => array('type' => 'string'),
		'type' => array('type' => 'string', 'enum' => array('published', 'sticky', 'static', 'draft')),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$allowed = array('published', 'sticky', 'static', 'draft');
		$key = mcp_resolve_page_key($a);
		$newType = mcp_arg($a, 'type', '');
		$p = mcp_page($key);
		if (!in_array($newType, $allowed, true)) {
			mcp_fail('Недопустимый тип.');
		}
		$current = $pages->db[$key]['type'];
		if (!in_array($current, $allowed, true)) {
			mcp_fail('Тип «' . $current . '» так не меняется — используйте bludit_page_edit.');
		}
		if ($current === $newType) {
			return array('message' => 'Тип не изменился.', 'key' => $key, 'type' => $newType);
		}
		mcp_check_page_owner($key);
		if ($current === 'static' && $newType !== 'static' && count($p->children()) > 0) {
			mcp_fail('Нельзя сменить тип, пока у страницы есть дочерние.');
		}
		if ($pages->setField($key, 'type', $newType) === false) {
			mcp_fail('Не удалось сменить тип.');
		}
		return array('message' => 'Тип изменён.', 'key' => $key, 'from' => $current, 'type' => $newType);
	},
);

$TOOLS['bludit_pages_reorder'] = array(
	'description' => 'Задать порядок страниц (поле position) — для сайтов с сортировкой по позиции и статических страниц/меню. Передайте ключи в нужном порядке.',
	'schema' => array('type' => 'object', 'required' => array('keys'), 'properties' => array(
		'keys' => array('type' => 'array', 'items' => array('type' => 'string')),
	)),
	'roles' => array('admin', 'editor'),
	'run' => function ($a) {
		global $pages;
		$keys = (array) mcp_arg($a, 'keys', array());
		foreach ($keys as $k) {
			if (!$pages->exists($k)) {
				mcp_fail('Страница не найдена: ' . $k);
			}
		}
		$result = array();
		foreach (array_values($keys) as $i => $k) {
			ob_start();
			$nk = mcp_core_edit($k, array('position' => $i + 1));
			ob_end_clean();
			$result[] = array('key' => $nk, 'position' => $i + 1);
		}
		return array('message' => 'Порядок сохранён.', 'items' => $result);
	},
);

// ---------------------------------------------------------------- Категории
$TOOLS['bludit_categories_list'] = array(
	'description' => 'Все категории: ключ, название, описание, шаблон, число страниц.',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $categories;
		$out = array();
		foreach ($categories->db as $key => $c) {
			$out[] = array('key' => $key, 'name' => $c['name'], 'description' => $c['description'], 'template' => $c['template'], 'pagesCount' => count($c['list']), 'permalink' => DOMAIN_CATEGORIES . $key);
		}
		return $out;
	},
);

$TOOLS['bludit_category_get'] = array(
	'description' => 'Категория и список её страниц.',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array('key' => array('type' => 'string'))),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $categories, $pages;
		$key = mcp_arg($a, 'key', '');
		if (!$categories->exists($key)) {
			mcp_fail('Категория не найдена: ' . $key);
		}
		$c = $categories->db[$key];
		$list = array();
		foreach ($c['list'] as $pk) {
			if ($pages->exists($pk)) {
				$list[] = array('key' => $pk, 'title' => $pages->db[$pk]['title'], 'type' => $pages->db[$pk]['type'], 'date' => $pages->db[$pk]['date']);
			}
		}
		return array('key' => $key, 'name' => $c['name'], 'description' => $c['description'], 'template' => $c['template'], 'permalink' => DOMAIN_CATEGORIES . $key, 'pages' => $list);
	},
);

$TOOLS['bludit_category_create'] = array(
	'description' => 'Создать категорию штатной функцией createCategory().',
	'schema' => array('type' => 'object', 'required' => array('name'), 'properties' => array(
		'name' => array('type' => 'string'),
		'description' => array('type' => 'string'),
		'template' => array('type' => 'string'),
		'key' => array('type' => 'string', 'description' => 'Желаемый ключ/URL (по умолчанию из названия)'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $categories;
		$name = trim((string) mcp_arg($a, 'name', ''));
		$before = $categories->keys();
		mcp_clear_alert();
		if (!createCategory(array('name' => $name, 'description' => (string) mcp_arg($a, 'description', '')))) {
			mcp_fail(mcp_alert_message('Категория не создана.'));
		}
		$new = array_values(array_diff($categories->keys(), $before));
		$key = $new ? $new[0] : Text::cleanUrl($name);
		$wantKey = mcp_arg($a, 'key', '');
		$template = (string) mcp_arg($a, 'template', '');
		if (($wantKey !== '' && Text::cleanUrl($wantKey) !== $key) || $template !== '') {
			$newKey = $wantKey !== '' ? Text::cleanUrl($wantKey) : $key;
			mcp_clear_alert();
			if (!editCategory(array('oldKey' => $key, 'newKey' => $newKey, 'name' => $name, 'description' => (string) mcp_arg($a, 'description', ''), 'template' => $template))) {
				mcp_fail(mcp_alert_message('Категория создана с ключом ' . $key . ', но сменить ключ/шаблон не удалось.'));
			}
			$key = $newKey;
		}
		return array('message' => 'Категория создана.', 'key' => $key, 'name' => $name);
	},
);

$TOOLS['bludit_category_edit'] = array(
	'description' => 'Изменить категорию штатной функцией editCategory(): название, описание, шаблон, ключ (при смене ключа страницы переносятся автоматически).',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array(
		'key' => array('type' => 'string', 'description' => 'Текущий ключ'),
		'name' => array('type' => 'string'),
		'description' => array('type' => 'string'),
		'template' => array('type' => 'string'),
		'new_key' => array('type' => 'string'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $categories;
		$key = mcp_arg($a, 'key', '');
		if (!$categories->exists($key)) {
			mcp_fail('Категория не найдена: ' . $key);
		}
		$c = $categories->db[$key];
		$newKey = mcp_arg($a, 'new_key', '');
		$newKey = $newKey !== '' ? Text::cleanUrl($newKey) : $key;
		$args = array(
			'oldKey' => $key,
			'newKey' => $newKey,
			'name' => (string) mcp_arg($a, 'name', $c['name']),
			'description' => (string) mcp_arg($a, 'description', $c['description']),
			'template' => (string) mcp_arg($a, 'template', $c['template']),
		);
		mcp_clear_alert();
		if (!editCategory($args)) {
			mcp_fail(mcp_alert_message('editCategory() вернула ошибку.'));
		}
		return array('message' => 'Категория сохранена.', 'key' => $newKey);
	},
);

$TOOLS['bludit_category_delete'] = array(
	'description' => 'Удалить категорию штатной функцией deleteCategory(). Ядро не трогает страницы; можно передать move_to — тогда страницы сначала переносятся в другую категорию (через editPage), либо move_to="" — оставить без категории.',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array(
		'key' => array('type' => 'string'),
		'move_to' => array('type' => 'string', 'description' => 'Ключ категории для переноса страниц; "" — убрать категорию у страниц'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $categories, $pages;
		$key = mcp_arg($a, 'key', '');
		if (!$categories->exists($key)) {
			mcp_fail('Категория не найдена: ' . $key);
		}
		$moved = array();
		if (array_key_exists('move_to', $a)) {
			$to = (string) $a['move_to'];
			if ($to !== '' && (!$categories->exists($to) || $to === $key)) {
				mcp_fail('Категория для переноса не найдена: ' . $to);
			}
			foreach ($pages->db as $pk => $row) {
				if ($row['category'] === $key) {
					ob_start();
					mcp_core_edit($pk, array('category' => $to));
					ob_end_clean();
					$moved[] = $pk;
				}
			}
		}
		deleteCategory(array('oldKey' => $key));
		mcp_clear_alert();
		return array('message' => 'Категория удалена.', 'movedPages' => $moved);
	},
);

// ---------------------------------------------------------------- Теги
$TOOLS['bludit_tags_list'] = array(
	'description' => 'Все теги: ключ, название, число страниц.',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $tags;
		$out = array();
		foreach ($tags->db as $key => $t) {
			$out[] = array('key' => $key, 'name' => $t['name'], 'pagesCount' => count($t['list']), 'permalink' => DOMAIN_TAGS . $key);
		}
		return $out;
	},
);

$TOOLS['bludit_tag_get'] = array(
	'description' => 'Тег и список его страниц.',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array('key' => array('type' => 'string'))),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $tags, $pages;
		$key = Text::cleanUrl(mcp_arg($a, 'key', ''));
		if (!$tags->exists($key)) {
			mcp_fail('Тег не найден: ' . $key);
		}
		$list = array();
		foreach ($tags->db[$key]['list'] as $pk) {
			if ($pages->exists($pk)) {
				$list[] = array('key' => $pk, 'title' => $pages->db[$pk]['title'], 'type' => $pages->db[$pk]['type']);
			}
		}
		return array('key' => $key, 'name' => $tags->db[$key]['name'], 'permalink' => DOMAIN_TAGS . $key, 'pages' => $list);
	},
);

$TOOLS['bludit_tag_rename'] = array(
	'description' => 'Переименовать или слить тег: на всех страницах тег заменяется новым через editPage() (с хуками). В Bludit теги живут в страницах, отдельной таблицы нет.',
	'schema' => array('type' => 'object', 'required' => array('key', 'new_name'), 'properties' => array(
		'key' => array('type' => 'string', 'description' => 'Ключ или название текущего тега'),
		'new_name' => array('type' => 'string'),
	)),
	'roles' => array('admin', 'editor'),
	'run' => function ($a) {
		global $pages;
		$old = Text::cleanUrl(mcp_arg($a, 'key', ''));
		$newName = trim((string) mcp_arg($a, 'new_name', ''));
		if ($newName === '') {
			mcp_fail('new_name пуст.');
		}
		$changed = array();
		foreach ($pages->db as $pk => $row) {
			if (isset($row['tags'][$old])) {
				$t = $row['tags'];
				unset($t[$old]);
				$t[Text::cleanUrl($newName)] = $newName;
				ob_start();
				mcp_core_edit($pk, array('tags' => implode(',', array_values($t))));
				ob_end_clean();
				$changed[] = $pk;
			}
		}
		if (!$changed) {
			mcp_fail('Тег не найден ни на одной странице: ' . $old);
		}
		return array('message' => 'Тег переименован.', 'pages' => $changed);
	},
);

$TOOLS['bludit_tag_delete'] = array(
	'description' => 'Убрать тег со всех страниц (через editPage(), с хуками).',
	'schema' => array('type' => 'object', 'required' => array('key'), 'properties' => array('key' => array('type' => 'string'))),
	'roles' => array('admin', 'editor'),
	'run' => function ($a) {
		global $pages;
		$old = Text::cleanUrl(mcp_arg($a, 'key', ''));
		$changed = array();
		foreach ($pages->db as $pk => $row) {
			if (isset($row['tags'][$old])) {
				$t = $row['tags'];
				unset($t[$old]);
				ob_start();
				mcp_core_edit($pk, array('tags' => implode(',', array_values($t))));
				ob_end_clean();
				$changed[] = $pk;
			}
		}
		if (!$changed) {
			mcp_fail('Тег не найден ни на одной странице: ' . $old);
		}
		return array('message' => 'Тег удалён со страниц.', 'pages' => $changed);
	},
);

// ---------------------------------------------------------------- Медиа
$TOOLS['bludit_image_upload'] = array(
	'description' => 'Загрузить картинку как Media Manager (transformImage(): чистка имени, проверка MIME, миниатюра). Источник — url или base64. page — ключ страницы, к которой привязать (если в настройках включена привязка картинок к страницам). set_cover=true — сразу сделать обложкой страницы.',
	'schema' => array('type' => 'object', 'properties' => array(
		'url' => array('type' => 'string'),
		'base64' => array('type' => 'string', 'description' => 'Данные картинки (можно data:image/...;base64,...)'),
		'filename' => array('type' => 'string', 'description' => 'Имя файла (иначе из URL или по типу)'),
		'page' => array('type' => 'string', 'description' => 'Ключ страницы'),
		'set_cover' => array('type' => 'boolean'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		$pageKey = (string) mcp_arg($a, 'page', '');
		if ($pageKey !== '') {
			mcp_page($pageKey);
			mcp_check_page_owner($pageKey);
		}
		if (mcp_arg($a, 'set_cover', false) && $pageKey === '') {
			mcp_fail('Для set_cover нужен page.');
		}
		$d = mcp_image_dirs($pageKey);
		$f = mcp_fetch_to_tmp($a, 'image');
		if (!in_array($f['ext'], $GLOBALS['ALLOWED_IMG_EXTENSION'], true)) {
			@unlink($f['tmp']);
			mcp_fail('Тип файла не поддерживается. Разрешено: ' . implode(', ', $GLOBALS['ALLOWED_IMG_EXTENSION']));
		}
		$mime = Filesystem::mimeType($f['tmp']);
		if ($mime === false || !in_array($mime, $GLOBALS['ALLOWED_IMG_MIMETYPES'], true)) {
			@unlink($f['tmp']);
			mcp_fail('MIME-тип не поддерживается: ' . ($mime ? $mime : 'неизвестен'));
		}
		if (!Filesystem::directoryExists($d['thumbs'])) {
			Filesystem::mkdir($d['thumbs'], true);
		}
		// transformImage() берёт имя из файла — переименуем tmp в чистое имя
		$tmpClean = PATH_TMP . $f['name'];
		if ($tmpClean !== $f['tmp']) {
			Filesystem::mv($f['tmp'], $tmpClean);
		}
		$image = transformImage($tmpClean, $d['dir'], $d['thumbs']);
		if (!$image) {
			@unlink($tmpClean);
			mcp_fail('transformImage() не смогла обработать картинку.');
		}
		chmod($image, 0644);
		$filename = Filesystem::filename($image);
		$result = array(
			'message' => 'Картинка загружена.',
			'filename' => $filename,
			'url' => $d['url'] . $filename,
			'thumbnail' => is_file($d['thumbs'] . $filename) ? $d['thumbsUrl'] . $filename : '',
			'markdown' => '![](' . $d['url'] . $filename . ')',
			'html' => '<img src="' . $d['url'] . $filename . '" alt="">',
		);
		if (mcp_arg($a, 'set_cover', false)) {
			ob_start();
			$nk = mcp_core_edit($pageKey, array('coverImage' => $filename));
			ob_end_clean();
			$result['coverSetFor'] = $nk;
		}
		return $result;
	},
);

$TOOLS['bludit_images_list'] = array(
	'description' => 'Картинки Media Manager: общие (без page) или конкретной страницы (если включена привязка к страницам).',
	'schema' => array('type' => 'object', 'properties' => array(
		'page' => array('type' => 'string'),
		'limit' => array('type' => 'integer', 'description' => 'По умолчанию 100'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		$d = mcp_image_dirs((string) mcp_arg($a, 'page', ''));
		$limit = max(1, (int) mcp_arg($a, 'limit', 100));
		if (!Filesystem::directoryExists($d['dir'])) {
			return array('items' => array());
		}
		$chunks = mediaManagerListImages($d['dir'], $d['thumbs'], $limit);
		$items = array();
		if (!empty($chunks[0])) {
			foreach ($chunks[0] as $it) {
				$items[] = array('filename' => $it['filename'], 'url' => $d['url'] . $it['filename'], 'thumbnail' => $it['thumbnail'] ? $d['thumbsUrl'] . $it['thumbnail'] : '');
			}
		}
		return array('directory' => $d['url'], 'items' => $items);
	},
);

$TOOLS['bludit_image_delete'] = array(
	'description' => 'Удалить картинку и её миниатюру (как ajax/delete-image.php).',
	'schema' => array('type' => 'object', 'required' => array('filename'), 'properties' => array(
		'filename' => array('type' => 'string'),
		'page' => array('type' => 'string'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		$pageKey = (string) mcp_arg($a, 'page', '');
		if ($pageKey !== '') {
			mcp_check_page_owner($pageKey);
		} elseif (mcp_role() === 'author') {
			mcp_fail('Автор может удалять только картинки своих страниц (укажите page).');
		}
		$d = mcp_image_dirs($pageKey);
		$filename = basename((string) mcp_arg($a, 'filename', ''));
		if ($filename === '' || !Sanitize::pathFile($d['dir'] . $filename)) {
			mcp_fail('Файл не найден: ' . $filename);
		}
		Filesystem::rmfile($d['dir'] . $filename);
		if (Sanitize::pathFile($d['thumbs'] . $filename) && is_file($d['thumbs'] . $filename)) {
			Filesystem::rmfile($d['thumbs'] . $filename);
		}
		return array('message' => 'Картинка удалена.', 'filename' => $filename);
	},
);

$TOOLS['bludit_file_upload'] = array(
	'description' => 'Прикрепить файл к странице (pdf, zip, mp3, docx и др. из списка разрешённых Bludit). Источник — url или base64.',
	'schema' => array('type' => 'object', 'required' => array('page'), 'properties' => array(
		'page' => array('type' => 'string'),
		'url' => array('type' => 'string'),
		'base64' => array('type' => 'string'),
		'filename' => array('type' => 'string'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$pageKey = (string) mcp_arg($a, 'page', '');
		mcp_page($pageKey);
		mcp_check_page_owner($pageKey);
		$f = mcp_fetch_to_tmp($a, 'file');
		if (!in_array($f['ext'], $GLOBALS['ALLOWED_FILE_EXTENSIONS'], true)) {
			@unlink($f['tmp']);
			mcp_fail('Тип файла не разрешён. Разрешено: ' . implode(', ', $GLOBALS['ALLOWED_FILE_EXTENSIONS']));
		}
		$uuid = $pages->getUUID($pageKey);
		$dir = PATH_UPLOADS_PAGES . $uuid . DS;
		if (!Filesystem::directoryExists($dir)) {
			Filesystem::mkdir($dir, true);
		}
		$name = Filesystem::nextFilename($f['name'], $dir);
		if (!Filesystem::mv($f['tmp'], $dir . $name)) {
			@unlink($f['tmp']);
			mcp_fail('Не удалось переместить файл.');
		}
		chmod($dir . $name, 0644);
		return array('message' => 'Файл загружен.', 'filename' => $name, 'url' => DOMAIN_UPLOADS_PAGES . $uuid . '/' . $name, 'size' => $f['size']);
	},
);

$TOOLS['bludit_files_list'] = array(
	'description' => 'Файлы, загруженные к странице (любые типы).',
	'schema' => array('type' => 'object', 'required' => array('page'), 'properties' => array('page' => array('type' => 'string'))),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$pageKey = (string) mcp_arg($a, 'page', '');
		mcp_page($pageKey);
		$uuid = $pages->getUUID($pageKey);
		$dir = PATH_UPLOADS_PAGES . $uuid . DS;
		$items = array();
		if (Filesystem::directoryExists($dir)) {
			foreach (Filesystem::listFiles($dir, '*', '*', true, false) as $file) {
				if (is_dir($file)) continue;
				$n = basename($file);
				$items[] = array('filename' => $n, 'url' => DOMAIN_UPLOADS_PAGES . $uuid . '/' . $n, 'mime' => Filesystem::mimeType($file), 'size' => Filesystem::getSize($file));
			}
		}
		return array('page' => $pageKey, 'uuid' => $uuid, 'items' => $items);
	},
);

$TOOLS['bludit_file_delete'] = array(
	'description' => 'Удалить файл, прикреплённый к странице.',
	'schema' => array('type' => 'object', 'required' => array('page', 'filename'), 'properties' => array(
		'page' => array('type' => 'string'), 'filename' => array('type' => 'string'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages;
		$pageKey = (string) mcp_arg($a, 'page', '');
		mcp_page($pageKey);
		mcp_check_page_owner($pageKey);
		$uuid = $pages->getUUID($pageKey);
		$dir = PATH_UPLOADS_PAGES . $uuid . DS;
		$n = basename((string) mcp_arg($a, 'filename', ''));
		if ($n === '' || !Sanitize::pathFile($dir . $n)) {
			mcp_fail('Файл не найден: ' . $n);
		}
		Filesystem::rmfile($dir . $n);
		if (is_file($dir . 'thumbnails' . DS . $n)) {
			Filesystem::rmfile($dir . 'thumbnails' . DS . $n);
		}
		return array('message' => 'Файл удалён.', 'filename' => $n);
	},
);

$TOOLS['bludit_images_optimize'] = array(
	'description' => 'Сжать уже загруженные картинки (JPEG, PNG, WebP) штатным классом Bludit Image, при желании уменьшив слишком широкие. Файлы сохраняются под теми же именами, поэтому ссылки в статьях не меняются. Файл заменяется, только если стал заметно меньше. Оригиналы по умолчанию копируются в bl-content/mcp-backup/. dry_run=true — только посчитать экономию. GIF и SVG не трогаются. Работает порциями: если в ответе есть next_offset, вызовите ещё раз с этим offset.',
	'schema' => array('type' => 'object', 'properties' => array(
		'scope'       => array('type' => 'string', 'enum' => array('page', 'common', 'all'), 'description' => 'page — картинки одной страницы (нужен page), common — общая папка uploads, all — всё (по умолчанию)'),
		'page'        => array('type' => 'string', 'description' => 'Ключ страницы для scope=page'),
		'quality'     => array('type' => 'integer', 'minimum' => 40, 'maximum' => 95, 'description' => 'Качество JPEG/WebP, по умолчанию 82. PNG всегда пережимается без потерь'),
		'max_width'   => array('type' => 'integer', 'minimum' => 320, 'description' => 'Уменьшить картинки шире этого значения (пропорционально). Не задано — размеры не меняются'),
		'min_saving'  => array('type' => 'integer', 'minimum' => 1, 'maximum' => 90, 'description' => 'Заменять, только если файл уменьшился хотя бы на столько процентов (по умолчанию 10 — так уже сжатые файлы не пережимаются повторно)'),
		'thumbnails'  => array('type' => 'boolean', 'description' => 'Сжимать и миниатюры (по умолчанию true, без изменения размера)'),
		'backup'      => array('type' => 'boolean', 'description' => 'Сохранить оригиналы в bl-content/mcp-backup/ (по умолчанию true)'),
		'dry_run'     => array('type' => 'boolean', 'description' => 'Ничего не менять, только отчёт о возможной экономии'),
		'offset'      => array('type' => 'integer', 'minimum' => 0, 'description' => 'Продолжить с этой позиции (из next_offset)'),
		'limit'       => array('type' => 'integer', 'minimum' => 1, 'maximum' => 500, 'description' => 'Файлов за вызов, по умолчанию 100'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $pages, $syslog;

		$scope     = mcp_arg($a, 'scope', mcp_arg($a, 'page', '') !== '' ? 'page' : 'all');
		$pageKey   = (string) mcp_arg($a, 'page', '');
		$quality   = min(95, max(40, (int) mcp_arg($a, 'quality', 82)));
		$maxWidth  = (int) mcp_arg($a, 'max_width', 0);
		$minSaving = min(90, max(1, (int) mcp_arg($a, 'min_saving', 10)));
		$withThumb = (bool) mcp_arg($a, 'thumbnails', true);
		$backup    = (bool) mcp_arg($a, 'backup', true);
		$dryRun    = (bool) mcp_arg($a, 'dry_run', false);
		$offset    = max(0, (int) mcp_arg($a, 'offset', 0));
		$limit     = min(500, max(1, (int) mcp_arg($a, 'limit', 100)));

		if (mcp_role() === 'author' && $scope !== 'page') {
			mcp_fail('Автор может сжимать только картинки своих страниц (scope=page).');
		}
		if (!function_exists('imagecreatetruecolor')) {
			mcp_fail('На сервере нет расширения GD.');
		}
		@set_time_limit(0);
		@ini_set('memory_limit', '512M');

		// Каталоги: [путь, URL, это миниатюры]
		$dirs = array();
		$addPageDirs = function ($uuid) use (&$dirs, $withThumb) {
			$d = PATH_UPLOADS_PAGES . $uuid . DS;
			if (is_dir($d) && !is_link(rtrim($d, DS))) {
				$dirs[] = array($d, DOMAIN_UPLOADS_PAGES . $uuid . '/', false);
				if ($withThumb && is_dir($d . 'thumbnails')) {
					$dirs[] = array($d . 'thumbnails' . DS, DOMAIN_UPLOADS_PAGES . $uuid . '/thumbnails/', true);
				}
			}
		};
		if ($scope === 'page') {
			if ($pageKey === '') {
				mcp_fail('Для scope=page укажите page.');
			}
			mcp_page($pageKey);
			mcp_check_page_owner($pageKey);
			$addPageDirs($pages->getUUID($pageKey));
		} else {
			$dirs[] = array(PATH_UPLOADS, DOMAIN_UPLOADS, false);
			if ($withThumb) {
				$dirs[] = array(PATH_UPLOADS_THUMBNAILS, DOMAIN_UPLOADS_THUMBNAILS, true);
			}
			if ($scope === 'all') {
				foreach ($pages->db as $row) {
					if (!empty($row['uuid'])) {
						$addPageDirs($row['uuid']);
					}
				}
			}
		}

		// Список файлов (стабильный порядок, чтобы offset работал между вызовами)
		$files = array();
		foreach ($dirs as $d) {
			$list = glob($d[0] . '*.{jpg,jpeg,png,webp,JPG,JPEG,PNG,WEBP}', GLOB_BRACE);
			if (!$list) continue;
			sort($list, SORT_STRING);
			foreach ($list as $f) {
				if (is_file($f) && !is_link($f)) {
					$files[] = array($f, $d[1] . basename($f), $d[2]);
				}
			}
		}
		$total = count($files);
		$batch = array_slice($files, $offset, $limit);

		$backupRoot = PATH_CONTENT . 'mcp-backup' . DS . date('Ymd-His') . DS;
		if (!Filesystem::directoryExists(PATH_TMP)) {
			Filesystem::mkdir(PATH_TMP, true);
		}

		$stats = array('checked' => 0, 'optimized' => 0, 'skipped' => 0, 'bytesBefore' => 0, 'bytesAfter' => 0);
		$items = array();
		foreach ($batch as $entry) {
			list($file, $url, $isThumb) = $entry;
			$stats['checked']++;
			$ext = Text::lowercase(pathinfo($file, PATHINFO_EXTENSION));
			$before = filesize($file);
			$info = @getimagesize($file);
			$rec = array('file' => $url, 'before' => $before);

			if ($info === false) {
				$rec['skipped'] = 'не удалось прочитать картинку';
			} elseif ($info[0] * $info[1] > 40000000) {
				$rec['skipped'] = 'слишком большая (больше 40 Мп)';
			} elseif (in_array($ext, array('jpg', 'jpeg'), true) && function_exists('exif_read_data') && ($exif = @exif_read_data($file)) && !empty($exif['Orientation']) && (int) $exif['Orientation'] !== 1) {
				$rec['skipped'] = 'фото с EXIF-поворотом — после пережатия оно бы перевернулось';
			}
			if (isset($rec['skipped'])) {
				$stats['skipped']++;
				$items[] = $rec;
				continue;
			}

			$w = $info[0];
			$targetW = ($maxWidth > 0 && !$isThumb && $w > $maxWidth) ? $maxWidth : $w;
			$tmp = PATH_TMP . 'mcp-opt-' . uniqid() . '.' . $ext;

			$img = new Image();
			if ($img->setImage($file, $targetW, 1000000, 'landscape') === false) {
				$rec['skipped'] = 'GD не может открыть этот формат';
				$stats['skipped']++;
				$items[] = $rec;
				continue;
			}
			// Для PNG качество 0 в Bludit Image = максимальное сжатие без потерь
			$img->saveImage($tmp, $ext === 'png' ? 0 : $quality);
			unset($img);
			clearstatcache();

			if (!is_file($tmp) || filesize($tmp) === 0) {
				@unlink($tmp);
				$rec['skipped'] = 'не удалось сохранить результат';
				$stats['skipped']++;
				$items[] = $rec;
				continue;
			}
			$after = filesize($tmp);
			$rec['after'] = $after;
			$rec['savedPercent'] = round((1 - $after / $before) * 100, 1);
			if ($targetW !== $w) {
				$rec['resized'] = $w . '→' . $targetW . 'px';
			}

			if ($after > $before * (1 - $minSaving / 100)) {
				@unlink($tmp);
				$rec['skipped'] = 'экономия меньше ' . $minSaving . '%';
				$stats['skipped']++;
				$items[] = $rec;
				continue;
			}

			$stats['bytesBefore'] += $before;
			$stats['bytesAfter'] += $after;

			if ($dryRun) {
				@unlink($tmp);
				$rec['wouldOptimize'] = true;
				$stats['optimized']++;
				$items[] = $rec;
				continue;
			}

			if ($backup) {
				$rel = substr($file, strlen(PATH_UPLOADS));
				$dest = $backupRoot . $rel;
				if (!Filesystem::directoryExists(dirname($dest))) {
					Filesystem::mkdir(dirname($dest), true);
				}
				if (!copy($file, $dest)) {
					@unlink($tmp);
					mcp_fail('Не удалось сделать резервную копию ' . $file . ' — остановлено, ничего не заменено.');
				}
			}
			if (!rename($tmp, $file)) {
				@unlink($tmp);
				$rec['skipped'] = 'не удалось заменить файл (права?)';
				$stats['skipped']++;
				$items[] = $rec;
				continue;
			}
			chmod($file, 0644);
			$rec['optimized'] = true;
			$stats['optimized']++;
			$items[] = $rec;
		}

		$saved = $stats['bytesBefore'] - $stats['bytesAfter'];
		if (!$dryRun && $stats['optimized'] > 0) {
			$syslog->add(array('dictionaryKey' => 'images-optimized', 'notes' => $stats['optimized'] . ' files, -' . round($saved / 1048576, 2) . ' MB'));
		}

		$result = array(
			'message' => $dryRun ? 'Проверка без изменений.' : 'Готово.',
			'totalFiles' => $total,
			'offset' => $offset,
			'processed' => count($batch),
			'optimized' => $stats['optimized'],
			'skipped' => $stats['skipped'],
			'savedBytes' => $saved,
			'savedMB' => round($saved / 1048576, 2),
			'items' => $items,
		);
		if ($offset + count($batch) < $total) {
			$result['next_offset'] = $offset + count($batch);
		}
		if (!$dryRun && $backup && $stats['optimized'] > 0) {
			$result['backup'] = 'bl-content/mcp-backup/' . basename(rtrim($backupRoot, DS)) . '/';
		}
		return $result;
	},
);

// ---------------------------------------------------------------- Пользователи
$TOOLS['bludit_users_list'] = array(
	'description' => 'Пользователи: логин, роль, email, имя, статус (активен/отключён), дата регистрации.',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $users;
		$out = array();
		foreach ($users->db as $u => $r) {
			$out[] = array('username' => $u, 'role' => $r['role'], 'email' => $r['email'], 'firstName' => $r['firstName'], 'lastName' => $r['lastName'], 'nickname' => $r['nickname'], 'enabled' => $r['password'] !== '!', 'registered' => $r['registered']);
		}
		return $out;
	},
);

$TOOLS['bludit_user_get'] = array(
	'description' => 'Профиль пользователя (без пароля и токенов). Не-админ видит только себя.',
	'schema' => array('type' => 'object', 'properties' => array('username' => array('type' => 'string', 'description' => 'По умолчанию — текущий'))),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $users;
		$u = (string) mcp_arg($a, 'username', mcp_user());
		if (mcp_role() !== 'admin' && $u !== mcp_user()) {
			mcp_fail('Можно смотреть только свой профиль.');
		}
		if (!$users->exists($u)) {
			mcp_fail('Пользователь не найден: ' . $u);
		}
		$user = new User($u);
		$data = $user->json(true);
		$row = $users->getUserDB($u);
		$data['role'] = $row['role'];
		$data['email'] = $row['email'];
		$data['registered'] = $row['registered'];
		$data['enabled'] = $row['password'] !== '!';
		return $data;
	},
);

$TOOLS['bludit_user_create'] = array(
	'description' => 'Создать пользователя штатной функцией createUser() (проверки логина и длины пароля).',
	'schema' => array('type' => 'object', 'required' => array('username', 'password', 'role'), 'properties' => array(
		'username' => array('type' => 'string'),
		'password' => array('type' => 'string', 'description' => 'Минимум 6 символов'),
		'role' => array('type' => 'string', 'enum' => array('admin', 'editor', 'author')),
		'email' => array('type' => 'string'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		$args = array(
			'new_username' => (string) mcp_arg($a, 'username', ''),
			'new_password' => (string) mcp_arg($a, 'password', ''),
			'confirm_password' => (string) mcp_arg($a, 'password', ''),
			'role' => (string) mcp_arg($a, 'role', 'author'),
			'email' => (string) mcp_arg($a, 'email', ''),
		);
		if (!in_array($args['role'], array('admin', 'editor', 'author'), true)) {
			mcp_fail('Недопустимая роль.');
		}
		mcp_clear_alert();
		if (!createUser($args)) {
			mcp_fail(mcp_alert_message('Пользователь не создан.'));
		}
		return array('message' => 'Пользователь создан.', 'username' => Text::removeSpecialCharacters($args['new_username']));
	},
);

$TOOLS['bludit_user_edit'] = array(
	'description' => 'Изменить профиль штатной функцией editUser(). Не-админ правит только себя и не может менять роль.',
	'schema' => array('type' => 'object', 'properties' => array(
		'username' => array('type' => 'string', 'description' => 'По умолчанию — текущий'),
		'role' => array('type' => 'string', 'enum' => array('admin', 'editor', 'author')),
		'email' => array('type' => 'string'), 'firstName' => array('type' => 'string'), 'lastName' => array('type' => 'string'),
		'nickname' => array('type' => 'string'), 'description' => array('type' => 'string'),
		'twitter' => array('type' => 'string'), 'facebook' => array('type' => 'string'), 'codepen' => array('type' => 'string'),
		'instagram' => array('type' => 'string'), 'github' => array('type' => 'string'), 'gitlab' => array('type' => 'string'),
		'linkedin' => array('type' => 'string'), 'mastodon' => array('type' => 'string'), 'vk' => array('type' => 'string'),
		'youtube' => array('type' => 'string'), 'bluesky' => array('type' => 'string'),
	)),
	'roles' => array('admin', 'editor', 'author'),
	'run' => function ($a) {
		global $users;
		$args = is_array($a) ? $a : array();
		if (mcp_role() !== 'admin') {
			$args['username'] = mcp_user();
			unset($args['role']);
		}
		if (empty($args['username'])) {
			$args['username'] = mcp_user();
		}
		if (!$users->exists($args['username'])) {
			mcp_fail('Пользователь не найден: ' . $args['username']);
		}
		unset($args['password'], $args['salt'], $args['tokenAuth'], $args['tokenRemember'], $args['registered'], $args['tokenAuthTTL']);
		if (isset($args['role']) && !in_array($args['role'], array('admin', 'editor', 'author'), true)) {
			mcp_fail('Недопустимая роль.');
		}
		if (isset($args['role']) && $args['username'] === 'admin' && $args['role'] !== 'admin') {
			mcp_fail('Пользователю admin нельзя менять роль.');
		}
		if (!editUser($args)) {
			mcp_fail('editUser() вернула ошибку.');
		}
		return array('message' => 'Профиль сохранён.', 'username' => $args['username']);
	},
);

$TOOLS['bludit_user_password'] = array(
	'description' => 'Сменить пароль другого пользователя штатной функцией changeUserPassword(). Bludit при смене пароля генерирует новый токен, поэтому свой пароль через коннектор менять нельзя (коннектор потерял бы доступ) — это делается в админке.',
	'schema' => array('type' => 'object', 'required' => array('username', 'password'), 'properties' => array(
		'username' => array('type' => 'string'),
		'password' => array('type' => 'string', 'description' => 'Минимум 6 символов'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		$u = (string) mcp_arg($a, 'username', '');
		if (mcp_role() !== 'admin') {
			mcp_fail('Менять пароли других пользователей может только admin; свой пароль меняйте в админке.');
		}
		if ($u === '' || $u === mcp_user()) {
			mcp_fail('Свой пароль меняйте в админке: Bludit при смене пароля меняет токен, и коннектор перестанет работать.');
		}
		$pw = (string) mcp_arg($a, 'password', '');
		mcp_clear_alert();
		if (!changeUserPassword(array('username' => $u, 'newPassword' => $pw, 'confirmPassword' => $pw))) {
			mcp_fail(mcp_alert_message('Пароль не изменён.'));
		}
		mcp_clear_alert();
		return array('message' => 'Пароль изменён.', 'username' => $u);
	},
);

$TOOLS['bludit_user_disable'] = array(
	'description' => 'Отключить пользователя штатной функцией disableUser() (вход и токен перестают работать).',
	'schema' => array('type' => 'object', 'required' => array('username'), 'properties' => array('username' => array('type' => 'string'))),
	'roles' => array('admin'),
	'run' => function ($a) {
		$u = (string) mcp_arg($a, 'username', '');
		if ($u === mcp_user()) {
			mcp_fail('Нельзя отключить самого себя — коннектор потеряет доступ.');
		}
		if (!disableUser(array('username' => $u))) {
			mcp_fail('disableUser() вернула ошибку (пользователь не найден?).');
		}
		return array('message' => 'Пользователь отключён.', 'username' => $u);
	},
);

$TOOLS['bludit_user_delete'] = array(
	'description' => 'Удалить пользователя штатной функцией deleteUser(): его страницы либо передаются текущему админу (по умолчанию), либо удаляются (delete_content=true).',
	'schema' => array('type' => 'object', 'required' => array('username'), 'properties' => array(
		'username' => array('type' => 'string'),
		'delete_content' => array('type' => 'boolean'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		$u = (string) mcp_arg($a, 'username', '');
		if ($u === mcp_user()) {
			mcp_fail('Нельзя удалить самого себя.');
		}
		if (!deleteUser(array('username' => $u, 'deleteContent' => (bool) mcp_arg($a, 'delete_content', false)))) {
			mcp_fail('deleteUser() вернула ошибку (admin удалить нельзя; проверьте логин).');
		}
		return array('message' => 'Пользователь удалён.', 'username' => $u);
	},
);

// ---------------------------------------------------------------- Плагины
$TOOLS['bludit_plugins_list'] = array(
	'description' => 'Все плагины: активен ли, версия, позиция, текущие настройки и их схема.',
	'schema' => array('type' => 'object', 'properties' => array('only_active' => array('type' => 'boolean'))),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $plugins;
		$onlyActive = (bool) mcp_arg($a, 'only_active', false);
		$out = array();
		foreach ($plugins['all'] as $cls => $p) {
			if ($onlyActive && !$p->installed()) continue;
			$out[] = mcp_plugin_info($cls, $p);
		}
		return $out;
	},
);

$TOOLS['bludit_plugin_activate'] = array(
	'description' => 'Включить плагин штатной функцией activatePlugin().',
	'schema' => array('type' => 'object', 'required' => array('plugin'), 'properties' => array('plugin' => array('type' => 'string', 'description' => 'Класс (pluginSitemap) или папка (sitemap)'))),
	'roles' => array('admin'),
	'run' => function ($a) {
		list($cls, $p) = mcp_find_plugin(mcp_arg($a, 'plugin', ''));
		if ($p->installed()) {
			return array('message' => 'Плагин уже включён.', 'plugin' => mcp_plugin_info($cls, $p));
		}
		ob_start();
		$ok = activatePlugin($cls);
		ob_end_clean();
		mcp_clear_alert();
		if (!$ok) {
			mcp_fail('activatePlugin() вернула ошибку.');
		}
		return array('message' => 'Плагин включён.', 'plugin' => mcp_plugin_info($cls, $p));
	},
);

$TOOLS['bludit_plugin_deactivate'] = array(
	'description' => 'Выключить плагин штатной функцией deactivatePlugin(). Настройки плагина при этом удаляются (так устроен Bludit).',
	'schema' => array('type' => 'object', 'required' => array('plugin'), 'properties' => array('plugin' => array('type' => 'string'))),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $site;
		list($cls, $p) = mcp_find_plugin(mcp_arg($a, 'plugin', ''));
		if ($p->directoryName() === $site->theme()) {
			mcp_fail('Это плагин активной темы — смените тему вместо отключения.');
		}
		if (!$p->installed()) {
			return array('message' => 'Плагин уже выключен.');
		}
		ob_start();
		$ok = deactivatePlugin($cls);
		ob_end_clean();
		mcp_clear_alert();
		if (!$ok) {
			mcp_fail('deactivatePlugin() вернула ошибку.');
		}
		return array('message' => 'Плагин выключен.', 'plugin' => $cls);
	},
);

$TOOLS['bludit_plugin_configure'] = array(
	'description' => 'Сохранить настройки плагина так же, как форма «Настроить» в админке: штатный $plugin->post() + syslog. Передайте только меняемые поля (ключи — из settingsSchema).',
	'schema' => array('type' => 'object', 'required' => array('plugin', 'settings'), 'properties' => array(
		'plugin' => array('type' => 'string'),
		'settings' => array('type' => 'object'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $syslog;
		list($cls, $p) = mcp_find_plugin(mcp_arg($a, 'plugin', ''));
		if (!$p->installed()) {
			mcp_fail('Плагин выключен — сначала bludit_plugin_activate.');
		}
		$settings = mcp_arg($a, 'settings', array());
		if (!is_array($settings) || !$settings) {
			mcp_fail('settings пуст.');
		}
		$unknown = array_diff(array_keys($settings), array_keys($p->dbFields));
		if ($unknown) {
			mcp_fail('Неизвестные поля: ' . implode(', ', $unknown) . '. Доступны: ' . implode(', ', array_keys($p->dbFields)));
		}
		$post = array();
		foreach ($settings as $k => $v) {
			if (is_bool($v)) {
				$v = $v ? 'true' : 'false';
			} elseif (is_array($v)) {
				$v = json_encode($v, JSON_UNESCAPED_UNICODE);
			}
			$post[$k] = (string) $v;
		}
		$savedPost = $_POST;
		$_POST = $post;
		$syslog->add(array('dictionaryKey' => 'plugin-configured', 'notes' => $p->name()));
		ob_start();
		$ok = $p->post();
		ob_end_clean();
		$_POST = $savedPost;
		if ($ok === false) {
			mcp_fail('Плагин не сохранил настройки.');
		}
		return array('message' => 'Настройки плагина сохранены.', 'plugin' => mcp_plugin_info($cls, $p));
	},
);

$TOOLS['bludit_plugins_reorder'] = array(
	'description' => 'Порядок плагинов в сайдбаре темы — штатная changePluginsPosition().',
	'schema' => array('type' => 'object', 'required' => array('plugins'), 'properties' => array(
		'plugins' => array('type' => 'array', 'items' => array('type' => 'string'), 'description' => 'Классы плагинов по порядку'),
	)),
	'roles' => array('admin'),
	'run' => function ($a) {
		$list = array();
		foreach ((array) mcp_arg($a, 'plugins', array()) as $name) {
			list($cls) = mcp_find_plugin($name);
			$list[] = $cls;
		}
		changePluginsPosition($list);
		mcp_clear_alert();
		return array('message' => 'Порядок сохранён.', 'order' => $list);
	},
);

// ---------------------------------------------------------------- Темы
$TOOLS['bludit_themes_list'] = array(
	'description' => 'Установленные темы и активная тема.',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $site;
		$out = array();
		foreach (Filesystem::listDirectories(PATH_THEMES) as $dir) {
			$name = basename($dir);
			$meta = array();
			if (is_file($dir . DS . 'metadata.json')) {
				$meta = json_decode(file_get_contents($dir . DS . 'metadata.json'), true);
			}
			$out[] = array(
				'directory' => $name,
				'active' => $name === $site->theme(),
				'version' => isset($meta['version']) ? $meta['version'] : '',
				'author' => isset($meta['author']) ? $meta['author'] : '',
				'website' => isset($meta['website']) ? $meta['website'] : '',
			);
		}
		return array('active' => $site->theme(), 'themes' => $out);
	},
);

$TOOLS['bludit_theme_activate'] = array(
	'description' => 'Сменить тему штатной функцией activateTheme() (отключает плагин старой темы, запускает install.php новой, включает её плагин).',
	'schema' => array('type' => 'object', 'required' => array('theme'), 'properties' => array('theme' => array('type' => 'string', 'description' => 'Папка темы'))),
	'roles' => array('admin'),
	'run' => function ($a) {
		$theme = basename((string) mcp_arg($a, 'theme', ''));
		if ($theme === '' || !is_dir(PATH_THEMES . $theme)) {
			mcp_fail('Тема не найдена: ' . $theme);
		}
		ob_start();
		$ok = activateTheme($theme);
		ob_end_clean();
		mcp_clear_alert();
		if (!$ok) {
			mcp_fail('activateTheme() вернула ошибку.');
		}
		return array('message' => 'Тема активирована.', 'theme' => $theme);
	},
);

// ---------------------------------------------------------------- Сервис
$TOOLS['bludit_syslog'] = array(
	'description' => 'Журнал действий Bludit (syslog): кто, что и когда менял — в том числе действия через этот коннектор.',
	'schema' => array('type' => 'object', 'properties' => array('limit' => array('type' => 'integer', 'description' => 'По умолчанию 50'))),
	'roles' => array('admin'),
	'run' => function ($a) {
		global $syslog, $L;
		$limit = max(1, (int) mcp_arg($a, 'limit', 50));
		$out = array();
		foreach (array_slice($syslog->db, 0, $limit) as $r) {
			$out[] = array('date' => $r['date'], 'user' => $r['username'], 'action' => $L->g($r['dictionaryKey']), 'actionKey' => $r['dictionaryKey'], 'notes' => $r['notes'], 'method' => isset($r['method']) ? $r['method'] : '');
		}
		return $out;
	},
);

$TOOLS['bludit_reindex'] = array(
	'description' => 'Пересобрать индексы категорий и тегов и опубликовать отложенные страницы, у которых наступила дата (reindexCategories, reindexTags, scheduler).',
	'schema' => array('type' => 'object', 'properties' => new stdClass()),
	'roles' => array('admin', 'editor'),
	'run' => function ($a) {
		global $pages;
		ob_start();
		$published = $pages->scheduler();
		if ($published) {
			Theme::plugins('afterPageCreate');
		}
		reindexCategories();
		reindexTags();
		ob_end_clean();
		return array('message' => 'Индексы пересобраны.', 'scheduledPublished' => (bool) $published);
	},
);

// ============================================================================
// MCP / JSON-RPC
// ============================================================================

function mcp_tools_for_role($tools)
{
	$role = mcp_role();
	$out = array();
	foreach ($tools as $name => $t) {
		if (in_array($role, $t['roles'], true)) {
			$out[] = array('name' => $name, 'description' => $t['description'], 'inputSchema' => $t['schema']);
		}
	}
	return $out;
}

function mcp_handle($req, $tools)
{
	if (!is_array($req) || !isset($req['method'])) {
		return array('jsonrpc' => '2.0', 'id' => null, 'error' => array('code' => -32600, 'message' => 'Invalid Request'));
	}
	$id = array_key_exists('id', $req) ? $req['id'] : null;
	$isNotification = !array_key_exists('id', $req);
	$method = $req['method'];
	$params = isset($req['params']) && is_array($req['params']) ? $req['params'] : array();

	if ($isNotification) {
		return null;
	}

	switch ($method) {
		case 'initialize':
			$supported = array('2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05');
			$want = isset($params['protocolVersion']) ? $params['protocolVersion'] : '';
			$version = in_array($want, $supported, true) ? $want : $supported[1];
			return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array(
				'protocolVersion' => $version,
				'capabilities' => array('tools' => array('listChanged' => false)),
				'serverInfo' => array('name' => MCP_SERVER_NAME, 'title' => 'Bludit (ядро)', 'version' => MCP_SERVER_VERSION),
				'instructions' => 'Управление сайтом Bludit ' . BLUDIT_VERSION . ' через функции ядра: страницы, категории, теги, медиа, пользователи, настройки, плагины, темы, журнал. Каждое изменение проходит через штатные функции (createPage/editPage/deletePage и др.), поэтому срабатывают хуки плагинов и пишется syslog. Ключ страницы = slug, у дочерних «родитель/потомок». Начинайте с bludit_info. Вы работаете как пользователь «' . mcp_user() . '» с ролью ' . mcp_role() . '.',
			));

		case 'ping':
			return array('jsonrpc' => '2.0', 'id' => $id, 'result' => new stdClass());

		case 'tools/list':
			return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('tools' => mcp_tools_for_role($tools)));

		case 'tools/call':
			$name = isset($params['name']) ? $params['name'] : '';
			$args = isset($params['arguments']) && is_array($params['arguments']) ? $params['arguments'] : array();
			if (!isset($tools[$name])) {
				return array('jsonrpc' => '2.0', 'id' => $id, 'error' => array('code' => -32602, 'message' => 'Unknown tool: ' . $name));
			}
			$tool = $tools[$name];
			$obLevel = ob_get_level();
			try {
				mcp_require_role($tool['roles']);
				ob_start();
				$data = call_user_func($tool['run'], $args);
				ob_end_clean();
				$text = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
				return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('content' => array(array('type' => 'text', 'text' => $text)), 'isError' => false));
			} catch (McpToolError $e) {
				while (ob_get_level() > $obLevel) { ob_end_clean(); }
				return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('content' => array(array('type' => 'text', 'text' => 'Ошибка: ' . $e->getMessage())), 'isError' => true));
			} catch (Throwable $e) {
				while (ob_get_level() > $obLevel) { ob_end_clean(); }
				error_log('[mcp-bludit] ' . $name . ': ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
				return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('content' => array(array('type' => 'text', 'text' => 'Внутренняя ошибка: ' . $e->getMessage())), 'isError' => true));
			}

		case 'resources/list':
			return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('resources' => array()));

		case 'prompts/list':
			return array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('prompts' => array()));

		default:
			return array('jsonrpc' => '2.0', 'id' => $id, 'error' => array('code' => -32601, 'message' => 'Method not found: ' . $method));
	}
}

$mcpRequest = json_decode($mcpRawBody, true);
if ($mcpRequest === null) {
	mcp_rpc_error(null, -32700, 'Parse error', 400);
}

// Пакетный запрос
if (is_array($mcpRequest) && array_keys($mcpRequest) === range(0, count($mcpRequest) - 1)) {
	$responses = array();
	foreach ($mcpRequest as $one) {
		$r = mcp_handle($one, $TOOLS);
		if ($r !== null) {
			$responses[] = $r;
		}
	}
	if (!$responses) {
		mcp_send(null, 202);
	}
	mcp_send($responses);
}

$response = mcp_handle($mcpRequest, $TOOLS);
if ($response === null) {
	mcp_send(null, 202);
}
mcp_send($response);
