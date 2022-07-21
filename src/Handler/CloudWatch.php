<?php

namespace Maxbanton\Cwh\Handler;

use Aws\CloudWatchLogs\CloudWatchLogsClient;
use Aws\CloudWatchLogs\Exception\CloudWatchLogsException;
use Exception;
use InvalidArgumentException;
use Monolog\Formatter\FormatterInterface;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Level;
use Monolog\LogRecord;
use DateTime;

class CloudWatch extends AbstractProcessingHandler
{
    /**
     * Requests per second limit (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html)
     */
    public const RPS_LIMIT = 5;

    /**
     * Event size limit (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html)
     */
    public const EVENT_SIZE_LIMIT = 262118; // 262144 - reserved 26

    private CloudWatchLogsClient $client;
    private string $group;
    private string $stream;
    private int $retention;
    private bool $initialized = false;
    private string $sequenceToken;
    private int $batchSize;
    /** @var LogRecord[] $buffer */
    private array $buffer = [];
    private array $tags = [];
    private bool $createGroup;
    /**
     * Data amount limit (http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html)
     */
    private int $dataAmountLimit = 1048576;
    private int $currentDataAmount = 0;
    private int $remainingRequests = self::RPS_LIMIT;
    private DateTime $savedTime;

    /**
     * CloudWatchLogs constructor.
     *
     *  Log group names must be unique within a region for an AWS account.
     *  Log group names can be between 1 and 512 characters long.
     *  Log group names consist of the following characters: a-z, A-Z, 0-9, '_' (underscore), '-' (hyphen),
     * '/' (forward slash), and '.' (period).
     *
     *  Log stream names must be unique within the log group.
     *  Log stream names can be between 1 and 512 characters long.
     *  The ':' (colon) and '*' (asterisk) characters are not allowed.
     *
     * @throws Exception
     */
    public function __construct(
        CloudWatchLogsClient $client,
        string $group,
        string $stream,
        int $retention = 14,
        int $batchSize = 10000,
        array $tags = [],
        int | Level $level = Level::Debug,
        bool $bubble = true,
        bool $createGroup = true,
    ) {
        if ($batchSize > 10000) {
            throw new InvalidArgumentException('Batch size can not be greater than 10000');
        }

        $this->client = $client;
        $this->group = $group;
        $this->stream = $stream;
        $this->retention = $retention;
        $this->batchSize = $batchSize;
        $this->tags = $tags;
        $this->createGroup = $createGroup;

        parent::__construct($level, $bubble);

        $this->savedTime = new DateTime();
    }

    protected function write(LogRecord $record): void
    {
        $records = $this->formatRecords($record);

        if (empty($records)) {
            return;
        }

        foreach ($records as $aRecord) {
            if ($this->currentDataAmount + $this->getMessageSize($aRecord) >= $this->dataAmountLimit) {
                $this->flushBuffer();
            }

            $this->addToBuffer($aRecord);

            if (count($this->buffer) >= $this->batchSize) {
                $this->flushBuffer();
            }
        }
    }

    private function addToBuffer(LogRecord $logRecord): void
    {
        $this->currentDataAmount += $this->getMessageSize($logRecord);
        $this->buffer[] = $logRecord;
    }

    private function flushBuffer(): void
    {
        if (empty($this->buffer)) {
            return;
        }

        if (! $this->initialized) {
            $this->initialize();
        }

        // send items, retry once with a fresh sequence token
        try {
            $this->send($this->buffer);
        } catch (CloudWatchLogsException $e) {
            $this->refreshSequenceToken();
            $this->send($this->buffer);
        }

        $this->buffer = [];
        $this->currentDataAmount = 0;
    }

    private function checkThrottle(): void
    {
        $current = new DateTime();
        $diff = $current->diff($this->savedTime)->s;
        $sameSecond = $diff === 0;

        if (! $sameSecond) {
            $this->remainingRequests = self::RPS_LIMIT;
            $this->savedTime = new DateTime();

            return;
        }

        if ($this->remainingRequests > 0) {
            $this->remainingRequests--;
            $this->savedTime = new DateTime();

            return;
        }

        sleep(1);
        $this->remainingRequests = self::RPS_LIMIT;
        $this->savedTime = new DateTime();
    }

    /**
     * http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
     */
    private function getMessageSize(LogRecord $record): int
    {
        return strlen($record->message) + 26;
    }

    /**
     * Event size in the batch can not be bigger than 256 KB
     * https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html
     */
    private function formatRecords(LogRecord $logRecord): array
    {
        $entries = str_split($logRecord->formatted, self::EVENT_SIZE_LIMIT);
        $timestamp = $logRecord->datetime->format('U.u') * 1000;
        $records = [];

        if (empty($entries)) {
            return $records;
        }

        foreach ($entries as $entry) {
            $records[] = [
                'message' => $entry,
                'timestamp' => $timestamp
            ];
        }

        return $records;
    }

    /**
     * The batch of events must satisfy the following constraints:
     *  - The maximum batch size is 1,048,576 bytes, and this size is calculated as the sum of all event messages in
     * UTF-8, plus 26 bytes for each log event.
     *  - None of the log events in the batch can be more than 2 hours in the future.
     *  - None of the log events in the batch can be older than 14 days or the retention period of the log group.
     *  - The log events in the batch must be in chronological ordered by their timestamp (the time the event occurred,
     * expressed as the number of milliseconds since Jan 1, 1970 00:00:00 UTC).
     *  - The maximum number of log events in a batch is 10,000.
     *  - A batch of log events in a single request cannot span more than 24 hours. Otherwise, the operation fails.
     *
     * @param LogRecord[] $logRecords
     *
     * @throws CloudWatchLogsException Thrown by putLogEvents for example in case of an
     *                                                               invalid sequence token
     */
    private function send(array $logRecords): void
    {
        // AWS expects to receive entries in chronological order...
        usort(
            $logRecords,
            static function (LogRecord $a, LogRecord $b) {
                return $a->datetime <=> $b->datetime;
            }
        );

        $data = [
            'logGroupName' => $this->group,
            'logStreamName' => $this->stream,
            'logEvents' => $logRecords,
        ];

        if (! empty($this->sequenceToken)) {
            $data['sequenceToken'] = $this->sequenceToken;
        }

        $this->checkThrottle();
        $response = $this->client->putLogEvents($data);
        $this->sequenceToken = $response->get('nextSequenceToken');
    }

    private function initializeGroup(): void
    {
        $existingGroups = $this->client->describeLogGroups(['logGroupNamePrefix' => $this->group])->get('logGroups');

        $existingGroupsNames = array_map(
            static function ($group) {
                return $group['logGroupName'];
            },
            $existingGroups
        );

        if (in_array($this->group, $existingGroupsNames, true)) {
            return;
        }

        $createLogGroupArguments = ['logGroupName' => $this->group];

        if (! empty($this->tags)) {
            $createLogGroupArguments['tags'] = $this->tags;
        }

        $this->client->createLogGroup($createLogGroupArguments);

        if (! $this->retention) {
            return;
        }

        $this->client->putRetentionPolicy([
            'logGroupName' => $this->group,
            'retentionInDays' => $this->retention,
        ]);
    }

    private function initialize(): void
    {
        if ($this->createGroup) {
            $this->initializeGroup();
        }

        $this->refreshSequenceToken();
    }

    private function refreshSequenceToken(): void
    {
        $existingStreams = $this->client->describeLogStreams([
            'logGroupName' => $this->group,
            'logStreamNamePrefix' => $this->stream,
        ])->get('logStreams');

        $existingStreamsNames = array_map(
            function ($stream) {
                if (($stream['logStreamName'] === $this->stream) && isset($stream['uploadSequenceToken'])) {
                    $this->sequenceToken = $stream['uploadSequenceToken'];
                }

                return $stream['logStreamName'];
            },
            $existingStreams
        );

        if (! in_array($this->stream, $existingStreamsNames, true)) {
            $this->client->createLogStream([
                'logGroupName' => $this->group,
                'logStreamName' => $this->stream
            ]);
        }

        $this->initialized = true;
    }

    protected function getDefaultFormatter(): FormatterInterface
    {
        return new LineFormatter(
        "%channel%: %level_name%: %message% %context% %extra%",
        null,
        false,
        true);
    }

    public function close(): void
    {
        $this->flushBuffer();
    }
}
