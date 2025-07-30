#ifndef PROGRESS_BAR_H
#define PROGRESS_BAR_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CLEAR_LINE "\033[2K"
#define CURSOR_HOME "\033[0G"
#define HIDE_CURSOR "\033[?25l"
#define SHOW_CURSOR "\033[?25h"

#define BAR_WIDTH 30

void progress_bar(const char *message, long long progress, long long total) {
    float ratio = (float)progress / total;
    int pos = (int)(BAR_WIDTH * ratio);

    // Clear the current line and hide cursor

    if (write(STDOUT_FILENO, HIDE_CURSOR, strlen(HIDE_CURSOR)) == -1) perror("write hide cursor");
    if (write(STDOUT_FILENO, CLEAR_LINE, strlen(CLEAR_LINE)) == -1) perror("write clear line");
    if (write(STDOUT_FILENO, CURSOR_HOME, strlen(CURSOR_HOME)) == -1) perror("write cursor home");


    // Construct the progress bar
    char bar[BAR_WIDTH + 1];
    memset(bar, '=', pos);
    memset(bar + pos, '-', BAR_WIDTH - pos);
    bar[BAR_WIDTH] = '\0';

    char buffer[256]; // Ensure buffer is large enough for all data
    int percent = (int)(ratio * 100.0);
    snprintf(buffer, sizeof(buffer), "%s: [%s] %d%% %lld/%lld", message, bar, percent, progress, total);
    write(STDOUT_FILENO, buffer, strlen(buffer));

    // Show cursor when done
    if (progress == total) {
        write(STDOUT_FILENO, SHOW_CURSOR, strlen(SHOW_CURSOR));
    }
}

#endif // PROGRESS_BAR_H

