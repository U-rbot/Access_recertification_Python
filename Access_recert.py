Login Page for Role Owners/Approvers
We will create a login page where role owners/approvers can enter their credentials to access their dashboard.

python
Copy code
# views.py

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    return render(request, 'login.html')
php
Copy code
<!-- login.html -->

{% extends 'base.html' %}

{% block content %}
    <form method="post">
        {% csrf_token %}
        <div>
            <label for="username">Username:</label>
            <input type="text" name="username" required>
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" name="password" required>
        </div>
        <button type="submit">Login</button>
    </form>
{% endblock %}
Dashboard to View All Assigned Reviews
Once role owners/approvers have logged in, they should be able to see all their assigned reviews on their dashboard. We can use a ListView to display all reviews.

python
Copy code
# views.py

from django.views.generic import ListView
from .models import Review

class ReviewListView(ListView):
    model = Review
    template_name = 'dashboard.html'
    context_object_name = 'reviews'

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Review.objects.all()
        else:
            return Review.objects.filter(owner=user)
php
Copy code
<!-- dashboard.html -->

{% extends 'base.html' %}

{% block content %}
    <h1>Dashboard</h1>
    <ul>
    {% for review in reviews %}
        <li><a href="{% url 'review_detail' review.id %}">{{ review.name }}</a></li>
    {% empty %}
        <li>No reviews found.</li>
    {% endfor %}
    </ul>
{% endblock %}
Review Page for Each Assigned Review
Clicking on a review name on the dashboard will take role owners/approvers to the review page, where they can view the access rights of each user in their role family and make decisions on access approval or revocation.

python
Copy code
# views.py

from django.shortcuts import render, get_object_or_404
from .models import Review

def review_detail_view(request, pk):
    review = get_object_or_404(Review, pk=pk)
    return render(request, 'review_detail.html', {'review': review})
php
Copy code
<!-- review_detail.html -->

{% extends 'base.html' %}

{% block content %}
    <h1>{{ review.name }}</h1>
    <table>
        <thead>
            <tr>
                <th>User</th>
                <th>Access Rights</th>
                <th>Decision</th>
                <th>Comments</th>
            </tr>
        </thead>
        <tbody>
        {% for user in review.users.all %}
            <tr>
                <td>{{ user }}</td>
                <td>{{ user.access_rights }}</td>
                <td>
                    <form method="post">
                        {% csrf_token %}
                        <input type="radio" name="decision" value="approve" required> Approve
                        <input type="



myrmvzjcrvkavlygsp@kvhrs.com
keep going
Sure, here's the next part of the code for the remaining features:

3. Review Page
Once the user selects a review from their dashboard, they will be taken to the review page where they can view the details of the review and make a decision on access approval or revocation. They will also have the option to add any necessary comments.

views.py
python
Copy code
@login_required
def review(request, review_id):
    review = get_object_or_404(Review, id=review_id)

    if request.method == 'POST':
        form = ReviewForm(request.POST, instance=review)
        if form.is_valid():
            form.save()
            messages.success(request, 'Review updated successfully.')
            return redirect('dashboard')
    else:
        form = ReviewForm(instance=review)

    return render(request, 'app/review.html', {'form': form, 'review': review})
forms.py
python
Copy code
class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ('decision', 'comment')
        widgets = {
            'decision': forms.RadioSelect,
            'comment': forms.Textarea(attrs={'rows': 3}),
        }
templates/app/review.html
html
Copy code
{% extends 'app/base.html' %}

{% block content %}
  <h2>{{ review.name }}</h2>
  <h4>Review Details:</h4>
  <ul>
    <li>User: {{ review.user }}</li>
    <li>Role: {{ review.role }}</li>
    <li>Access: {{ review.access }}</li>
  </ul>

  <form method="post" class="mt-4">
    {% csrf_token %}
    {{ form.as_p }}
    <button type="submit" class="btn btn-primary">Submit</button>
  </form>
{% endblock %}
4. Sign-off Button
Once the role owner has reviewed all the access rights in their role family, they can sign off on the review. This will indicate that the review is complete and trigger a notification to the role approver.

views.py
python
Copy code
@login_required
def signoff(request, review_id):
    review = get_object_or_404(Review, id=review_id)
    review.signed_off = True
    review.save()
    messages.success(request, 'Review signed off successfully.')
    return redirect('dashboard')
templates/app/dashboard.html
html
Copy code
{% extends 'app/base.html' %}

{% block content %}
  <h2>Dashboard</h2>
  <table class="table">
    <thead>
      <tr>
        <th>Review Name</th>
        <th>User</th>
        <th>Role</th>
        <th>Access</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      {% for review in reviews %}
        <tr>
          <td>{{ review.name }}</td>
          <td>{{ review.user }}</td>
          <td>{{ review.role }}</td>
          <td>{{ review.access }}</td>
          <td>
            {% if review.signed_off %}
              <span class="text-success">Signed Off</span>
            {% else %}
              <a href="{% url 'review' review.id %}" class="btn btn-primary btn-sm">Review</a>
              <a href="{% url 'signoff' review.id %}" class="btn btn-success btn-sm">Sign Off</a>
            {% endif %}
          </td>
        </tr>
      {% empty %}
        <tr>
          <td colspan="5" class="text-center">No reviews available.</td>



myrmvzjcrvkavlygsp@kvhrs.com
good keep going
Thank you! Here's the rest of the code for the Access Recertification Web Application:

views.py (continued)
python
Copy code
@login_required
def review_detail(request, review_id):
    review = Review.objects.get(id=review_id)
    user = request.user
    
    # Ensure that only the role owner or role approver assigned to the review can access it
    if user != review.role_owner and user not in review.role_approvers.all():
        return HttpResponseForbidden('You do not have access to this review.')
    
    # If the review is already signed off, redirect to the review history page
    if review.signed_off:
        return redirect('review_history')
    
    if request.method == 'POST':
        form = ReviewDecisionForm(request.POST)
        if form.is_valid():
            review_decision = form.save(commit=False)
            review_decision.review = review
            review_decision.decision_maker = user
            review_decision.save()
            
            # Update the access level of the user based on the decision
            if review_decision.decision == 'approve':
                review.user.access_level = review.access_level
            elif review_decision.decision == 'revoke':
                review.user.access_level = None
            review.user.save()
            
            # If all role approvers have made a decision, mark the review as signed off
            if review.role_approvers.count() == review.reviewdecisions.count():
                review.signed_off = True
                review.save()
                
                # Notify the role owner and role approvers that the review is complete
                recipients = list(review.role_approvers.all()) + [review.role_owner]
                subject = f'Review {review.id} for {review.user} complete'
                message = f'The review for {review.user} has been completed by all role approvers.'
                send_notification(recipients, subject, message)
                
                # Redirect to the dashboard with a success message
                messages.success(request, 'Review complete.')
                return redirect('dashboard')
                
    else:
        form = ReviewDecisionForm()
    
    return render(request, 'app/review_detail.html', {'review': review, 'form': form})


@login_required
def review_history(request):
    user = request.user
    
    # Retrieve all completed reviews for the user's role family
    reviews = Review.objects.filter(Q(role_owner=user) | Q(role_approvers=user), signed_off=True)
    
    return render(request, 'app/review_history.html', {'reviews': reviews})
urls.py
lua
Copy code
from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('review/<int:review_id>/', views.review_detail, name='review_detail'),
    path('review/history/', views.review_history, name='review_history'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
]
