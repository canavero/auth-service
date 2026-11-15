package store.auth;

import lombok.Builder;
import lombok.Data;
import lombok.experimental.Accessors;

@Builder @Data
@Accessors(fluent = true)
public class Register {

    private String name;
    private String email;
    private String password;

}
