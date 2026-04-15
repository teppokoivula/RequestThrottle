<?php

namespace ProcessWire;

/**
 * Request Throttle module
 *
 * Throttle requests for named resources based on timestamps and fingerprints.
 */
class RequestThrottle extends WireData implements Module, ConfigurableModule {

	const TABLE_NAME = 'request_throttle';

	protected $fingerprint = null;

	public static function getModuleInfo() {
		return [
			'title' => 'Request Throttle',
			'summary' => 'Throttle requests for named resources based on timestamps and fingerprints.',
			'version' => '0.0.5',
			'author' => 'Teppo Koivula',
			'autoload' => false,
			'singular' => true,
			'requires' => [
				'PHP>=7.4.0',
				'ProcessWire>=3.0.184',
			],
		];
	}

	public static function getDefaultData() {
		return [
			'max_requests' => 5,
			'time_in_minutes' => 5,
			'max_age_for_requests' => 60,
			'fingerprint_mode' => null,
		];
	}

	/**
	 * Populate the default config data
	 *
	 * ProcessWire will automatically overwrite it with anything the user has specifically configured.
	 * This is done in construct() rather than init() because ProcessWire populates config data after
	 * construct(), but before init().
	 */
	public function __construct() {
		foreach (self::getDefaultData() as $key => $value) {
			$this->$key = $value;
		}
	}

	public function getModuleConfigInputfields(array $data) {

		$fields = $this->wire(new InputfieldWrapper());

		// merge default config settings (custom values overwrite defaults)
		$defaults = self::getDefaultData();
		$data = array_merge($defaults, $data);

		// default value for max requests
		$max_requests = $this->wire(new InputfieldInteger());
		$max_requests->name = 'max_requests';
		$max_requests->value = $data['max_requests'] ?? 5;
		$max_requests->label = __('Max requests');
		$max_requests->description = __('Maximum number of requests allowed within the time frame.');
		$fields->add($max_requests);

		// default value for time frame
		$time_in_minutes = $this->wire(new InputfieldInteger());
		$time_in_minutes->name = 'time_in_minutes';
		$time_in_minutes->value = $data['time_in_minutes'] ?? 5;
		$time_in_minutes->label = __('Time in minutes');
		$time_in_minutes->description = __('Default value for time in minutes used when checking amount of requests made.');
		$fields->add($time_in_minutes);

		// maximum time to store requests for
		$max_age_for_requests = $this->wire(new InputfieldInteger());
		$max_age_for_requests->name = 'max_age_for_requests';
		$max_age_for_requests->value = $data['max_age_for_requests'] ?? 60;
		$max_age_for_requests->label = __('Max age for requests');
		$max_age_for_requests->description = __('Maximum age for requests in minutes.');
		$fields->add($max_age_for_requests);

		// fingerprint mode
		$fingerprint_mode = $this->wire(new InputfieldCheckboxes());
		$fingerprint_mode->name = 'fingerprint_mode';
		$fingerprint_mode->label = __('Fingerprint mode');
		$fingerprint_mode->description = __('Fingerprint mode to use. Leave empty to use whatever ProcessWire is currently configured to use.');
		$fingerprint_mode->notes = __('If you select multiple options, the fingerprint will be a combination of all selected options. If you leave this option empty and ProcessWire is configured not to use a fingerprint, default value for Session::getFingerprint() will be used.');
		$fingerprint_mode->optionColumns = 1;
		$fingerprint_mode->addOptions([
			2 => __('Remote IP'),
			4 => __('Forwarded/client IP'),
			8 => __('User agent'),
			16 => __('Accept header'),
		]);
		$fingerprint_mode->value = $data['fingerprint_mode'] ?? null;
		$fields->add($fingerprint_mode);

		return $fields;
	}

	/**
	 * Check if a request is allowed for a given resource
	 *
	 * Returns true if the request is within the configured limits, false if throttled.
	 * By default increments the request counter and cleans up expired entries.
	 *
	 * @param string $resource Resource identifier (e.g. 'password_reset', 'login')
	 * @param int|null $max_requests Max requests allowed (null = use module config)
	 * @param int|null $time_in_minutes Time window in minutes (null = use module config)
	 * @param string|null $fingerprint Client fingerprint (null = auto-detect)
	 * @param bool $increment Whether to increment the request counter
	 * @param bool $cleanup Whether to clean up expired entries
	 * @return bool True if request is allowed, false if throttled
	 */
	public function request(string $resource, ?int $max_requests = null, ?int $time_in_minutes = null, ?string $fingerprint = null, bool $increment = true, bool $cleanup = true): bool {

		$fingerprint = $fingerprint ?? $this->getFingerprint();

		$max_requests = $max_requests === null
			? $this->max_requests
			: $max_requests;
		if ($max_requests === null || (int) $max_requests != $max_requests || $max_requests < 1) {
			throw new WireException('Invalid value for $max_requests');
		}

		$timestamp = date('Y-m-d H:i:s', strtotime('-' . ($time_in_minutes ?: ($this->time_in_minutes ?: 5)) . ' minutes'));

		// clean up expired requests?
		if ($cleanup) {
			$this->cleanup();
		}

		// make sure there are no more than $max_requests within the provided time frame
		$select_stmt = $this->database->prepare("
			SELECT COUNT(*) AS `count`
			FROM `" . self::TABLE_NAME . "`
			WHERE `resource` = :resource
			AND `fingerprint` = :fingerprint
			AND `timestamp` > :timestamp
		");
		$select_stmt->bindValue(':resource', $resource, \PDO::PARAM_STR);
		$select_stmt->bindValue(':fingerprint', $fingerprint, \PDO::PARAM_STR);
		$select_stmt->bindValue(':timestamp', $timestamp, \PDO::PARAM_STR);
		$select_stmt->execute();
		$result = $select_stmt->fetch(\PDO::FETCH_ASSOC);

		// increment request count?
		if ($increment) {
			$this->increment($resource, $fingerprint);
		}

		return $result['count'] < $max_requests;
	}

	/**
	 * Check if a request is allowed without incrementing the counter
	 *
	 * @param string $resource Resource identifier
	 * @param int|null $max_requests Max requests allowed (null = use module config)
	 * @param int|null $time_in_minutes Time window in minutes (null = use module config)
	 * @return bool True if request would be allowed, false if throttled
	 */
	public function requestQuietly(string $resource, ?int $max_requests = null, ?int $time_in_minutes = null): bool {
		return $this->request($resource, $max_requests, $time_in_minutes, null, false);
	}

	/**
	 * Record a request for a given resource
	 *
	 * @param string $resource Resource identifier
	 * @param string|null $fingerprint Client fingerprint (null = auto-detect)
	 * @return void
	 */
	public function increment(string $resource, ?string $fingerprint = null) {

		$fingerprint = $fingerprint ?? $this->getFingerprint();

		// insert new request row
		$insert_stmt = $this->database->prepare("
			INSERT INTO `" . self::TABLE_NAME . "`
			(`resource`, `fingerprint`)
			VALUES
			(:resource, :fingerprint)
		");
		$insert_stmt->bindValue(':resource', $resource, \PDO::PARAM_STR);
		$insert_stmt->bindValue(':fingerprint', $fingerprint, \PDO::PARAM_STR);
		$insert_stmt->execute();
	}

	/**
	 * Delete expired request entries
	 *
	 * @return void
	 * @throws WireException If max_age_for_requests is invalid
	 */
	public function cleanup() {

		if (!$this->max_age_for_requests || (int) $this->max_age_for_requests != $this->max_age_for_requests || $this->max_age_for_requests < 1) {
			throw new WireException('Invalid value for $max_age_for_requests');
		}

		$delete_stmt = $this->database->prepare("
		DELETE FROM `" . self::TABLE_NAME . "`
		WHERE `timestamp` < :timestamp
		");
		$delete_stmt->bindValue(':timestamp', date('Y-m-d H:i:s', strtotime('-' . $this->max_age_for_requests . ' minutes')), \PDO::PARAM_STR);
		$delete_stmt->execute();
	}

	/**
	 * Get the client fingerprint for the current request
	 *
	 * Uses PW's Session::getFingerprint() with the configured fingerprint mode.
	 *
	 * @return string
	 */
	public function getFingerprint(): string {

		if (empty($this->fingerprint)) {

			$fingerprint_mode = null;
			if (!empty($this->fingerprint_mode)) {
				$fingerprint_mode = 0;
				foreach ($this->fingerprint_mode as $mode) {
					$fingerprint_mode |= $mode;
				}
			}

			$this->fingerprint = $this->session->getFingerprint(empty($fingerprint_mode)
				? ($this->config->sessionFingerprint ? null : true)
				: (int) $fingerprint_mode);
		}

		return $this->fingerprint;
	}

	public function ___install() {
		$charset = $this->config->dbCharset ?: 'utf8';
		$engine = $this->config->dbEngine ?: 'InnoDB';
		$this->database->exec("
		CREATE TABLE IF NOT EXISTS `" . self::TABLE_NAME . "` (
			`id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
			`resource` VARCHAR(255) NOT NULL,
			`fingerprint` VARCHAR(255) NOT NULL,
			`timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			INDEX `resource_fingerprint_timestamp` (`resource`, `fingerprint`, `timestamp`)
		) ENGINE=$engine DEFAULT CHARSET=$charset
		");
	}

	public function ___uninstall() {
		$this->database->exec("DROP TABLE IF EXISTS `" . self::TABLE_NAME . "`");
	}
}
