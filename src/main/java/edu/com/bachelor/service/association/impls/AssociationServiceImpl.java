package edu.com.bachelor.service.association.impls;

import edu.com.bachelor.model.Association;
import edu.com.bachelor.repository.AssociationRepository;
import edu.com.bachelor.service.association.IAssociationService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.NoSuchElementException;

@Service
@AllArgsConstructor
public class AssociationServiceImpl implements IAssociationService {
    private AssociationRepository repository;

    @Override
    public Association save(Association association) {
        if(association.getId() != null){
            return null;
        }
        association.setCreatedAt(LocalDateTime.now());
        return repository.save(association);
    }

    @Override
    public void delete(Long id) {
        repository.deleteById(id);
    }

    @Override
    public Association getOneById(Long id) {
        return repository.findById(id).orElseThrow(NoSuchElementException::new);
    }

    @Override
    public List<Association> getAll() {
        return repository.findAll();
    }

    @Override
    public Association update(Association association) {
        Association existingAssociation = repository.findById(association.getId()).orElseThrow(NoSuchElementException::new);
        existingAssociation.setName(association.getName());
        existingAssociation.setDescription(association.getDescription());
        existingAssociation.setPlace(association.getPlace());
        existingAssociation.setUsers(association.getUsers());
        existingAssociation.setEvents(association.getEvents());
        existingAssociation.setUpdatedAt(LocalDateTime.now());
        return repository.save(existingAssociation);
    }
}
