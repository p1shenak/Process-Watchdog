using System;
using System.Threading;
using System.Windows;

namespace ProcessWatchdog
{
    public partial class App : Application
    {
        // Уникальный ID для нашей программы
        private static string mutexId = "Global\\ProcessWatchdog_Unique_Mutex_ID_1337";
        private static Mutex myMutex;

        // Перехватываем момент старта приложения
        protected override void OnStartup(StartupEventArgs e)
        {
            bool isNewInstance;

            // Пытаемся создать системный маркер
            myMutex = new Mutex(true, mutexId, out isNewInstance);

            // Если он уже занят (программа уже работает) — закрываемся
            if (!isNewInstance)
            {
                myMutex.Dispose();
                Shutdown(); 
                return;
            }

            base.OnStartup(e);
        }

        // Освобождаем маркер, если закрыли оригинальную программу
        protected override void OnExit(ExitEventArgs e)
        {
            if (myMutex != null)
            {
                myMutex.ReleaseMutex();
                myMutex.Dispose();
            }
            base.OnExit(e);
        }
    }
}