package io.github.guinovaisz.gatekeeper.credential;

import java.time.*;
import java.util.*;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Bounded fake mailbox for local harnesses. Not a production delivery system. */
@Component
@Profile({"local","test"})
public class LocalRecoveryDelivery implements RecoveryDelivery {
    private record Message(String token,Instant expires) { @Override public String toString(){return "Message[redacted]";} }
    private final Map<UUID,Message> mailbox=new LinkedHashMap<>(); private final Clock clock;
    public LocalRecoveryDelivery(Clock clock) {this.clock=clock;}
    public synchronized void deliver(UUID id,String token) {
        mailbox.entrySet().removeIf(e->!clock.instant().isBefore(e.getValue().expires()));
        if(mailbox.size()>=100) mailbox.remove(mailbox.keySet().iterator().next());
        mailbox.put(id,new Message(token,clock.instant().plusSeconds(600)));
    }
    public synchronized String take(UUID id) {
        Message value=mailbox.remove(id);
        return value!=null && clock.instant().isBefore(value.expires())?value.token():null;
    }
}
