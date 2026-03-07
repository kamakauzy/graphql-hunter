package graphqlhunter;

import burp.api.montoya.logging.Logging;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public final class GraphQLHunterLogger
{
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss")
        .withZone(ZoneId.systemDefault());

    private final Logging logging;
    private final List<Consumer<String>> listeners = new CopyOnWriteArrayList<>();

    public GraphQLHunterLogger(Logging logging)
    {
        this.logging = logging;
    }

    public void addListener(Consumer<String> listener)
    {
        listeners.add(listener);
    }

    public void info(String message)
    {
        publish("INFO", message, false, null);
    }

    public void warn(String message)
    {
        publish("WARN", message, false, null);
    }

    public void error(String message, Throwable throwable)
    {
        publish("ERROR", message, true, throwable);
    }

    private void publish(String level, String message, boolean isError, Throwable throwable)
    {
        String line = "[" + TIMESTAMP.format(Instant.now()) + "] [" + level + "] " + message;
        if (logging != null)
        {
            if (isError)
            {
                if (throwable != null)
                {
                    logging.logToError(message, throwable);
                }
                else
                {
                    logging.logToError(message);
                }
                logging.raiseErrorEvent(message);
            }
            else
            {
                logging.logToOutput(line);
                logging.raiseInfoEvent(message);
            }
        }

        listeners.forEach(listener -> listener.accept(line));
    }
}
