#include "ratelimiter.h"
#include <vector>
#include <mutex>
#include <condition_variable>
#include <future>
#include <thread>
#include <functional>

struct RateLimitCommand {
	guint interval;
	GSourceFunc function;
	gpointer data;
};

class TokenBucket {
private:
    guint tokens;
    const guint maxTokens;
    const guint interval; // in milliseconds
    mutable std::mutex bucketMutex;
    std::condition_variable condVar;
public:
    explicit TokenBucket(guint rateLimitPerSecond)
        : tokens(rateLimitPerSecond), maxTokens(rateLimitPerSecond), interval(1000 / rateLimitPerSecond) {}

    bool acquire() {
        std::unique_lock<std::mutex> lock(bucketMutex);
        if (tokens > 0) {
            --tokens;
            return true;
        }
        return false;
    }

    void refill() {
        std::unique_lock<std::mutex> lock(bucketMutex);
        tokens = maxTokens;
        condVar.notify_all();
    }

    void waitForToken() {
        std::unique_lock<std::mutex> lock(bucketMutex);
        condVar.wait(lock, [this] { return tokens > 0; });
        --tokens;
    }
};

class EventLoop
{
public:
	/**
	 * @typedef Command
	 * @brief Type alias for a callable function with no arguments and no return value.
	 */
	typedef std::function<void()> Command;

private:
	/**
	 * @var writeBuffer
	 * @brief Buffer to store commands waiting to be executed.
	 */
	std::vector<Command> writeBuffer;

	/**
	 * @var commandsMutex
	 * @brief Mutex to synchronize access to the command buffer.
	 */
	mutable std::mutex commandsMutex;

	/**
	 * @var condVar
	 * @brief Condition variable to signal when new commands are available.
	 */
	std::condition_variable condVar;

	/**
	 * @var isRunning
	 * @brief Flag indicating whether the event loop is currently running.
	 */
	bool isRunning;

	/**
	 * @var loopThread
	 * @brief Dedicated thread for executing the event loop.
	 */
	std::thread loopThread;

	/**
	 * @fn loopFunction
	 * @brief Internal function executed by the dedicated thread to process commands.
	 *
	 * This function runs in an infinite loop until the event loop is stopped.
	 * It executes commands from the buffer in the order they were enqueued.
	 */
	void loopFunction();

	// Non-copyable and non-movable
	EventLoop(const EventLoop&) = delete;
	EventLoop(EventLoop&&) noexcept = delete;
	EventLoop& operator=(const EventLoop&) = delete;
	EventLoop& operator=(EventLoop&&) noexcept = delete;

public:
	/**
	 * @fn EventLoop
	 * @brief Constructor, initializes the event loop and starts the dedicated thread.
	 */
	EventLoop();

	/**
	 * @fn ~EventLoop
	 * @brief Destructor, stops the event loop and joins the dedicated thread.
	 */
	~EventLoop();

	/**
	 * @fn running
	 * @brief Checks whether the event loop is currently running.
	 *
	 * @return True if the event loop is running, false otherwise.
	 */
	bool running() const;

	/**
	 * @fn enqueue
	 * @brief Enqueues a command to be executed by the event loop.
	 *
	 * The command will be executed in the order it was received, within the dedicated thread.
	 *
	 * @param callable Command to be executed (rvalue reference to allow for temporary objects).
	 */
	void enqueue(Command&& callable);
	/**
	 * @fn enqueue
	 * @brief Enqueues a command to be executed by the event loop.
	 *
	 * The command will be executed in the order it was received, within the dedicated thread.
	 *
	 * @param callable Command to be executed.
	 */
	void enqueue(const Command& callable);

	/**
	 * @fn enqueueSync
	 * @brief Enqueues a command with arguments and waits for its completion.
	 *
	 * If called from the same thread as the event loop, the command is executed immediately.
	 * Otherwise, the command is enqueued and the function waits for its completion.
	 *
	 * @tparam Func Type of the callable function.
	 * @tparam Args Types of the function arguments.
	 * @param callable Callable function to be executed (forwarding reference).
	 * @param args Function arguments (forwarding references).
	 * @return The result of the executed function.
	 */
	template<typename Func, typename... Args> inline auto enqueueSync(Func&& callable, Args&&...args)
	{
		if (std::this_thread::get_id() == loopThread.get_id())
		{
			return std::invoke(
				std::forward<Func>(callable),
				std::forward<Args>(args)...);
		}

		using return_type = std::invoke_result_t<Func, Args...>;
		using packaged_task_type =
			std::packaged_task<return_type(Args&&...)>;

		packaged_task_type task(std::forward<Func>(callable));

		enqueue([task = std::move(task), args...]
		{
			task(std::forward<Args>(args)...);
		});

		return task.get_future().get();
	}

	/**
	 * @fn enqueueAsync
	 * @brief Enqueues a command with arguments and returns a future for its result.
	 *
	 * The command is executed asynchronously, and the returned future can be used to retrieve the result.
	 *
	 * @tparam Func Type of the callable function.
	 * @tparam Args Types of the function arguments.
	 * @param callable Callable function to be executed (forwarding reference).
	 * @param args Function arguments (forwarding references).
	 * @return A future representing the result of the executed function.
	 */
	template<typename Func, typename... Args> [[nodiscard]] inline auto enqueueAsync(Func&& callable, Args&&...args)
	{
		using return_type = std::invoke_result_t<Func, Args...>;
		using packaged_task_type = std::packaged_task<return_type()>;

		auto taskPtr = std::make_shared<packaged_task_type>(std::bind(
			std::forward<Func>(callable), std::forward<Args>(args)...));

		enqueue(std::bind(&packaged_task_type::operator(), taskPtr));

		return taskPtr->get_future();
	}
};

void EventLoop::loopFunction()
{
	std::vector<Command> readBuffer;
	while (isRunning)
	{
		{
			std::unique_lock<std::mutex> lock(commandsMutex);
			condVar.wait(lock, [this]
			{
				return !writeBuffer.empty();
			});
			std::swap(readBuffer, writeBuffer);
		}
		for (Command& func : readBuffer)
		{
				func();
		}
		readBuffer.clear();
	}
}

EventLoop::EventLoop()
	: isRunning(true), loopThread(&EventLoop::loopFunction, this)
{

}

EventLoop::~EventLoop()
{
    {
        std::lock_guard<std::mutex> lockguard(commandsMutex);
        isRunning = false;
        writeBuffer.clear();
    }
    condVar.notify_all();
	loopThread.join();
}

bool EventLoop::running() const
{
	return isRunning;
}

void EventLoop::enqueue(Command&& callable)
{
	{
		std::lock_guard<std::mutex> lockguard(commandsMutex);
		writeBuffer.emplace_back(std::move(callable));
	}
	condVar.notify_one();
}

void EventLoop::enqueue(const Command& callable)
{
	{
		std::lock_guard<std::mutex> lockguard(commandsMutex);
		writeBuffer.emplace_back(std::move(callable));
	}
	condVar.notify_one();
}

static std::unique_ptr<EventLoop> EVENT_LOOP = nullptr;
static std::unique_ptr<TokenBucket> TOKEN_BUCKET = nullptr;
static std::atomic<bool> refillThreadRunning{false};
static std::thread refillThread;

void initialize_rate_limiter(guint rateLimitPerSecond) {
	if (refillThreadRunning.exchange(true)) {
        return;  // Thread already running
    }
    if (!EVENT_LOOP) EVENT_LOOP = std::unique_ptr<EventLoop>(new EventLoop());
    if (!TOKEN_BUCKET) TOKEN_BUCKET = std::unique_ptr<TokenBucket>(new TokenBucket(rateLimitPerSecond));

    // Start a thread to refill tokens at a regular interval.
    refillThread = std::thread([refillThreadRunning = &refillThreadRunning]() {
        while (*refillThreadRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (TOKEN_BUCKET) {
                TOKEN_BUCKET->refill();
            }
        }
    });
	refillThread.detach();
}

void stop_rate_limiter() {
	refillThreadRunning = false;
	std::this_thread::sleep_for(std::chrono::seconds(1));
    if (EVENT_LOOP) {
        EVENT_LOOP.reset();
        EVENT_LOOP = nullptr;
    }
    if (TOKEN_BUCKET) {
        TOKEN_BUCKET.reset();
        TOKEN_BUCKET = nullptr;
    }
}

guint rlimited_timeout_add(guint interval, GSourceFunc function, gpointer data) {
    if (!EVENT_LOOP || !TOKEN_BUCKET) {
        g_warning("Rate limiter not initialized.");
        return 0;
    }

    EVENT_LOOP->enqueue([interval, function, data]() {
        TOKEN_BUCKET->waitForToken(); // Wait until a token is available
        if (function) {
            function(data);
        }
    });

    return 1; // Return a placeholder ID (or a meaningful one if task tracking is added).
}
