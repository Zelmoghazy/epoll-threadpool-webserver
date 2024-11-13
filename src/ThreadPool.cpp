#include <ThreadPool.h>

ThreadPool::ThreadPool() 
{
    // get as much threads as cpu cores
    const uint32_t num_threads = std::thread::hardware_concurrency(); 
    std::cout<< "number of threads created = " << num_threads << std::endl; 

    for (uint32_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(std::thread(&ThreadPool::ThreadLoop,this));
    }
}

ThreadPool::~ThreadPool() 
{
    std::unique_lock<std::mutex> lock(queue_mutex);

    should_terminate = true;

    lock.unlock();

    /* Join all the running threads */
    mutex_condition.notify_all();
    for (std::thread& active_thread : threads) {
        active_thread.join();
    }
    threads.clear();
}

void ThreadPool::ThreadLoop() 
{
    while (true) 
    {
        std::function<void()> job;
        
        std::unique_lock<std::mutex> lock(queue_mutex);

        mutex_condition.wait(lock, [this] {
            return (!jobs.empty() || should_terminate);
        });

        if (should_terminate) {
            return;
        }

        job = jobs.front();     // get task from task list
        jobs.pop();             // remove the task from the list because we are going to execute it

        lock.unlock();

        job();                 // Execute the task
    }
}

void ThreadPool::QueueJob(const std::function<void()>& job) 
{
    std::unique_lock<std::mutex> lock(queue_mutex);

    jobs.push(job);
    
    lock.unlock();

    mutex_condition.notify_one();
}

bool ThreadPool::busy() 
{
    bool poolbusy;
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        poolbusy = !jobs.empty();
    }
    return poolbusy;
}
