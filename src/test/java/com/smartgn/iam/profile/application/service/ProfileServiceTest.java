package com.smartgn.iam.profile.application.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.smartgn.iam.profile.application.port.in.CreateProfileCommand;
import com.smartgn.iam.profile.application.port.in.Requester;
import com.smartgn.iam.profile.application.port.in.UpdateProfileCommand;
import com.smartgn.iam.profile.application.port.out.ProfileRepository;
import com.smartgn.iam.profile.domain.exception.ProfileAccessDeniedException;
import com.smartgn.iam.profile.domain.exception.ProfileAlreadyExistsException;
import com.smartgn.iam.profile.domain.exception.ProfileNotFoundException;
import com.smartgn.iam.profile.domain.model.UserProfile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
class ProfileServiceTest {

    @Mock ProfileRepository profiles;
    @InjectMocks ProfileService service;

    private final UUID ownerId = UUID.randomUUID();
    private final UUID otherAccountId = UUID.randomUUID();
    private final UUID profileId = UUID.randomUUID();
    private final UserProfile profile =
            UserProfile.create(ownerId, "Ana", "Perez", "987654321", "123 Main Avenue");

    @Test
    void createsProfileTrimmingWhitespaceAndOptionalFields() {
        when(profiles.existsByAccountId(ownerId)).thenReturn(false);
        when(profiles.save(any(UserProfile.class))).thenAnswer(inv -> inv.getArgument(0));

        UserProfile createdProfile =
                service.create(new CreateProfileCommand(ownerId, "  Ana ", "Perez", "  ", null));

        assertEquals(ownerId, createdProfile.getAccountId());
        assertEquals("Ana", createdProfile.getFirstName());
        assertNull(createdProfile.getPhone());
        assertNull(createdProfile.getAddress());
    }

    @Test
    void rejectsSecondProfileForTheSameAccount() {
        when(profiles.existsByAccountId(ownerId)).thenReturn(true);

        assertThrows(
                ProfileAlreadyExistsException.class,
                () ->
                        service.create(
                                new CreateProfileCommand(ownerId, "Ana", "Perez", null, null)));
        verify(profiles, never()).save(any());
    }

    @Test
    void ownerCanReadTheirProfile() {
        when(profiles.findById(profileId)).thenReturn(Optional.of(profile));

        assertSame(profile, service.getById(profileId, new Requester(ownerId, false)));
    }

    @Test
    void anotherAccountCannotReadTheProfile() {
        when(profiles.findById(profileId)).thenReturn(Optional.of(profile));

        assertThrows(
                ProfileAccessDeniedException.class,
                () -> service.getById(profileId, new Requester(otherAccountId, false)));
    }

    @Test
    void superadminCanReadAnyProfile() {
        when(profiles.findById(profileId)).thenReturn(Optional.of(profile));

        assertSame(profile, service.getById(profileId, new Requester(otherAccountId, true)));
    }

    @Test
    void missingProfileRaisesNotFound() {
        when(profiles.findById(profileId)).thenReturn(Optional.empty());

        assertThrows(
                ProfileNotFoundException.class,
                () -> service.getById(profileId, new Requester(ownerId, false)));
    }

    @Test
    void ownerUpdatesTheirProfile() {
        when(profiles.findById(profileId)).thenReturn(Optional.of(profile));
        when(profiles.save(any(UserProfile.class))).thenAnswer(inv -> inv.getArgument(0));

        UserProfile updatedProfile =
                service.update(
                        new UpdateProfileCommand(
                                profileId, ownerId, "Ana Maria", "Perez", null, "5 Sun Street"));

        assertEquals("Ana Maria", updatedProfile.getFirstName());
        assertNull(updatedProfile.getPhone());
        assertEquals("5 Sun Street", updatedProfile.getAddress());
    }

    @Test
    void anotherAccountCannotUpdateTheProfile() {
        when(profiles.findById(profileId)).thenReturn(Optional.of(profile));

        assertThrows(
                ProfileAccessDeniedException.class,
                () ->
                        service.update(
                                new UpdateProfileCommand(
                                        profileId, otherAccountId, "X", "Y", null, null)));
        verify(profiles, never()).save(any());
    }

    @Test
    void superadminCannotModifyAnotherAccountsProfile() {
        when(profiles.findById(profileId)).thenReturn(Optional.of(profile));

        assertThrows(
                ProfileAccessDeniedException.class,
                () ->
                        service.update(
                                new UpdateProfileCommand(
                                        profileId, otherAccountId, "X", "Y", null, null)));
    }
}
