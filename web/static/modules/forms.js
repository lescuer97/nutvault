// modules/forms.js

// Init editable card name inputs
export function initCardInputs(root = document) {
  root.querySelectorAll('.card-name-input').forEach((input) => {
    const form = input.closest('form');
    if (!form) return;
    const saveBtn = form.querySelector('.card-save-btn');
    if (!saveBtn) return;

    const update = () => {
      if (input.value !== input.defaultValue) {
        saveBtn.classList.remove('hidden');
      } else {
        saveBtn.classList.add('hidden');
      }
    };

    input.addEventListener('input', update);
    input.addEventListener('change', update);

    // initialize
    update();

    form.addEventListener('submit', () => {
      saveBtn.classList.add('hidden');
      saveBtn.setAttribute('aria-busy', 'true');
    });
  });
}
